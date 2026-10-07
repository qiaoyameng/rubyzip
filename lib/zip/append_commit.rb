# frozen_string_literal: true

require 'json'

module Zip
  # Zip::AppendCommit implements the explicit "append revision" commit mode
  # used by Zip::File#commit_append.
  #
  # Instead of rewriting the whole archive like Zip::File#commit does, an
  # append commit writes a new *revision* at the end of the existing file:
  #
  #   [old revision bytes ...][new local records][new central directory][new EOCD]
  #
  # Entries that did not change keep pointing at their original local
  # records; their bytes are neither read nor recompressed. Only new,
  # removed and modified entries affect the new central directory, which is
  # the directory every normal reader finds at the tail of the file.
  #
  # Because the old bytes are left in place, removing or replacing an entry
  # only affects the latest directory: the old data is still physically
  # present in the file and old revisions remain readable through the
  # directory position recorded in their Receipt. This is explicitly *not*
  # a secure deletion mechanism - use Zip::File#commit (a full rewrite) if
  # removed data must actually be gone from the file.
  #
  # Crash safety:
  #
  # Before anything is written, a journal file (<path>.append-journal)
  # records the identity of the archive (device + inode) and the confirmed
  # length of the file - the tail position the new revision builds on. The
  # revision is then written in a fixed order: entry bodies, central
  # directory, end-of-central-directory record, and finally the completion
  # receipt (the journal's "completed" record). Success is only announced
  # after that completion marker is durable.
  #
  # If the process dies mid-revision, AppendCommit.recover uses the journal
  # - and only the journal - to return the file to its confirmed length. It
  # never scans the archive body for PK signatures to guess its state.
  module AppendCommit
    JOURNAL_SUFFIX = '.append-journal'
    JOURNAL_VERSION = 1

    # The value object returned by a successful append commit. It records
    # where the revision's central directory lives, which is everything
    # needed to open this exact revision again later (see
    # Zip::File.open_revision), even after newer revisions have been
    # appended on top of it.
    class Receipt
      attr_reader :path, :base_length, :cdir_offset, :cdir_size,
                  :eocd_offset, :entry_count, :end_length

      def initialize(path:, base_length:, cdir_offset:, cdir_size:,
                     eocd_offset:, entry_count:, end_length:)
        @path         = path
        @base_length  = base_length
        @cdir_offset  = cdir_offset
        @cdir_size    = cdir_size
        @eocd_offset  = eocd_offset
        @entry_count  = entry_count
        @end_length   = end_length
      end

      def to_h
        {
          'path'        => @path,
          'base_length' => @base_length,
          'cdir_offset' => @cdir_offset,
          'cdir_size'   => @cdir_size,
          'eocd_offset' => @eocd_offset,
          'entry_count' => @entry_count,
          'end_length'  => @end_length
        }
      end

      def self.from_h(hash)
        new(
          path:        hash['path'],
          base_length: hash['base_length'],
          cdir_offset: hash['cdir_offset'],
          cdir_size:   hash['cdir_size'],
          eocd_offset: hash['eocd_offset'],
          entry_count: hash['entry_count'],
          end_length:  hash['end_length']
        )
      end

      # Raises Zip::Error unless this revision's directory is still present
      # in the file (i.e. the file has not been truncated or rewritten
      # below the revision's end).
      def validate_present!
        return if @cdir_offset && @cdir_size &&
                  @cdir_offset >= 0 && @cdir_offset + @cdir_size <= ::File.size(@path)

        raise ::Zip::Error,
              "revision directory at #{@cdir_offset} (size #{@cdir_size}) is no longer " \
              "present in #{@path}"
      end
    end

    # The crash-recovery journal. A single JSON record in a sidecar file
    # next to the archive, written (and fsynced) before the revision starts
    # and again, marked completed, as the final completion receipt.
    class Journal # :nodoc:all
      def initialize(zip_path)
        @path = "#{zip_path}#{JOURNAL_SUFFIX}"
      end

      def begin(identity, confirmed_length)
        @identity = identity
        @confirmed_length = confirmed_length
        write('state'            => 'pending',
              'identity'         => identity,
              'confirmed_length' => confirmed_length,
              'started_at'       => ::Time.now.to_f)
      end

      def complete(receipt)
        write('state'            => 'completed',
              'identity'         => @identity,
              'confirmed_length' => @confirmed_length,
              'receipt'          => receipt.to_h,
              'completed_at'     => ::Time.now.to_f)
      end

      def delete
        ::FileUtils.rm_f(@path)
      end

      private

      def write(record)
        ::File.open(@path, 'w') do |file|
          file.write(JSON.generate(record.merge('version' => JOURNAL_VERSION)))
          file.fsync
        end
      end
    end

    class << self
      def journal_path(path)
        "#{path}#{JOURNAL_SUFFIX}"
      end

      # Appends a new revision describing +cdir+ to the archive at +path+.
      # Returns the revision's Receipt. Any incomplete revision left behind
      # by a previous crashed commit is rolled back first.
      #
      # +after_stage+ is an optional hook called with each completed stage
      # name (:journal, :body, :directory, :end_record, :receipt); it exists
      # so tests can inject faults between stages.
      def commit(path, cdir, suppress_extra_fields: false, after_stage: nil)
        recover(path)
        Committer.new(
          path, cdir,
          suppress_extra_fields: suppress_extra_fields,
          after_stage:           after_stage
        ).commit
      end

      # Brings the archive at +path+ back to a confirmed state after a
      # crashed append commit, using only the journal left by that commit:
      #
      # - a pending journal means the revision never completed, so the file
      #   is truncated back to the confirmed length recorded in the journal;
      # - a completed journal means the revision is durable and only the
      #   journal itself is cleaned up.
      #
      # Returns :truncated, :completed, or nil when there was no journal.
      # Raises Zip::Error if the journal does not match the file on disk -
      # recovery never guesses from the archive's contents.
      def recover(path)
        journal_file = journal_path(path)
        return nil unless ::File.exist?(journal_file)

        record = read_journal(journal_file, path)
        case record['state']
        when 'completed'
          ::File.unlink(journal_file)
          :completed
        when 'pending'
          truncate_to_confirmed_length(path, record['confirmed_length'])
          ::File.unlink(journal_file)
          :truncated
        else
          raise ::Zip::Error, "unknown state in append-commit journal #{journal_file}"
        end
      end

      # Returns a Receipt describing the revision currently at the tail of
      # the archive at +path+. Keep it to reopen exactly this revision with
      # Zip::File.open_revision after further revisions have been appended.
      def current_receipt(path)
        cdir = ::Zip::CentralDirectory.new
        ::File.open(path, 'rb') { |io| cdir.read_from_stream(io) }
        Receipt.new(
          path:        path,
          base_length: nil,
          cdir_offset: cdir.cdir_offset,
          cdir_size:   cdir.cdir_size,
          eocd_offset: cdir.eocd_offset,
          entry_count: cdir.entries.size,
          end_length:  ::File.size(path)
        )
      end

      private

      def read_journal(journal_file, path)
        record = JSON.parse(::File.read(journal_file))
        unless record['version'] == JOURNAL_VERSION
          raise ::Zip::Error, "unrecognised append-commit journal version in #{journal_file}"
        end

        verify_identity!(record, path)
        record
      rescue JSON::ParserError
        raise ::Zip::Error, "corrupt append-commit journal #{journal_file}"
      end

      def verify_identity!(record, path)
        unless ::File.exist?(path)
          raise ::Zip::Error,
                "append-commit journal exists for #{path}, but the archive itself is missing"
        end

        identity = record['identity'] || {}
        stat = ::File.stat(path)
        return if identity['dev'] == stat.dev && identity['ino'] == stat.ino

        raise ::Zip::Error,
              "append-commit journal for #{path} does not match the file on disk; " \
              'refusing to recover'
      end

      def truncate_to_confirmed_length(path, confirmed_length)
        size = ::File.size(path)
        if size < confirmed_length
          raise ::Zip::Error,
                "archive #{path} is shorter than the confirmed length recorded in its " \
                'append-commit journal'
        end

        ::File.truncate(path, confirmed_length) if size > confirmed_length
      end
    end

    # Performs a single append revision. The write order is fixed and
    # explicit: journal, entry bodies, central directory, end record, and
    # only then the completion receipt.
    class Committer # :nodoc:all
      def initialize(path, cdir, suppress_extra_fields:, after_stage:)
        @path = path
        @cdir = cdir
        @suppress_extra_fields = suppress_extra_fields
        @after_stage = after_stage
        @journal = Journal.new(path)
      end

      def commit
        bind
        write_revision
        complete
      end

      private

      # Bind the identity of the archive and the confirmed tail position
      # before writing anything.
      def bind
        ::FileUtils.touch(@path) unless ::File.exist?(@path)
        stat = ::File.stat(@path)
        @confirmed_length = stat.size
        @journal.begin({ 'dev' => stat.dev, 'ino' => stat.ino }, @confirmed_length)
        notify_stage(:journal)
      end

      def write_revision
        ::File.open(@path, 'r+b') do |io|
          io.seek(@confirmed_length, IO::SEEK_SET)
          write_body(io)
          notify_stage(:body)
          @cdir_offset, @cdir_size =
            @cdir.write_entries_to_stream(io, suppress_extra_fields: @suppress_extra_fields)
          notify_stage(:directory)
          @eocd_offset = @cdir.write_end_records_to_stream(io, @cdir_offset, @cdir_size)
          notify_stage(:end_record)
          io.fsync
        end
      end

      # The completion receipt is the very last write; the revision is only
      # announced as successful once it is durable.
      def complete
        receipt = Receipt.new(
          path:        @path,
          base_length: @confirmed_length,
          cdir_offset: @cdir_offset,
          cdir_size:   @cdir_size,
          eocd_offset: @eocd_offset,
          entry_count: @cdir.entries.size,
          end_length:  ::File.size(@path)
        )
        @journal.complete(receipt)
        notify_stage(:receipt)
        @journal.delete
        receipt
      end

      def notify_stage(stage)
        @after_stage&.call(stage, self)
      end

      # Only entries that are new or have been changed get a new local
      # record. Unchanged entries keep referencing their existing record.
      def write_body(io)
        @cdir.each do |entry|
          next unless body_needed?(entry)

          if entry.directory?
            entry.write_local_entry(io, suppress_extra_fields: @suppress_extra_fields)
          elsif entry.filepath || entry.kind_of?(::Zip::StreamableStream)
            write_fresh_entry(io, entry)
          else
            raw_copy_entry(io, entry)
          end
        end
      end

      def body_needed?(entry)
        entry.filepath || entry.kind_of?(::Zip::StreamableStream) || entry.dirty?
      end

      def write_fresh_entry(io, entry)
        entry.write_local_entry(io, suppress_extra_fields: @suppress_extra_fields)
        compressor = compressor_for(entry, io)
        entry.get_input_stream do |istream|
          while (chunk = istream.read(::Zip::IOExtras::CHUNK_SIZE))
            compressor << chunk
          end
        end
        compressor.finish
        entry.compressed_size =
          io.tell - entry.local_header_offset - entry.calculate_local_header_size
        entry.size = compressor.size
        entry.crc = compressor.crc
        rewrite_local_header(io, entry)
      end

      def raw_copy_entry(io, entry)
        src_pos = entry.local_header_offset
        entry.write_local_entry(io, suppress_extra_fields: @suppress_extra_fields)
        entry.get_raw_input_stream do |istream|
          istream.seek(src_pos, IO::SEEK_SET)
          ::Zip::Entry.read_local_entry(istream)
          ::Zip::IOExtras.copy_stream_n(io, istream, entry.compressed_size)
        end
      end

      def rewrite_local_header(io, entry)
        end_pos = io.tell
        io.pos = entry.local_header_offset
        entry.write_local_entry(io, suppress_extra_fields: @suppress_extra_fields, rewrite: true)
        io.pos = end_pos
      end

      def compressor_for(entry, io)
        case entry.compression_method
        when ::Zip::Entry::STORED
          ::Zip::PassThruCompressor.new(io)
        when ::Zip::Entry::DEFLATED
          ::Zip::Deflater.new(io, entry.compression_level)
        else
          raise ::Zip::CompressionMethodError, entry.compression_method
        end
      end
    end
  end
end
