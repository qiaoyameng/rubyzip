# frozen_string_literal: true

module Zip
  # RevisionJournal is the crash-recovery log for Zip::File's
  # append-revision commit. Before a revision starts modifying the archive,
  # the journal binds the archive's identity (device + inode) and its
  # confirmed tail position (the file length at which all previously
  # committed data ends). As the commit progresses through its stages the
  # journal records how far it got, and the final +complete+ state is the
  # completion marker: a revision is only considered committed once that
  # marker is durably written.
  #
  # Recovery (Zip::File.recover_append_revision) uses only this journal -
  # it never scans the archive body for signatures to guess its state. If
  # the last revision did not complete, the archive is truncated back to
  # the confirmed length recorded here, discarding the partial revision.
  class RevisionJournal # :nodoc:all
    SUFFIX = '.revjournal'
    FORMAT_VERSION = 'zip-revision-journal/1'

    # States, in the order the commit writes them: the completion marker
    # (+complete+) is only written after the body, central directory and
    # end-of-central-directory record are all durably on disk.
    STATES = %w[started body directory end_record complete].freeze

    class << self
      def path_for(zip_path)
        "#{zip_path}#{SUFFIX}"
      end

      # Binds the current identity and tail position of +zip_path+ in a
      # fresh journal with state +started+. Must be called before the
      # archive is modified.
      def start(zip_path, confirmed_length)
        stat = ::File.stat(zip_path)
        new(zip_path,
            'device'           => stat.dev,
            'inode'            => stat.ino,
            'confirmed_length' => confirmed_length,
            'state'            => 'started').tap(&:write)
      end

      # If a journal exists for +zip_path+, rolls the archive back to the
      # confirmed length recorded in it (unless the revision completed, in
      # which case the archive is already whole) and removes the journal.
      # Returns :rolled_back or :complete if a journal was found, nil
      # otherwise.
      #
      # Raises Zip::Error if the journal does not match the archive's
      # identity, or if the archive is shorter than the confirmed length -
      # in both cases the file is left untouched.
      def recover(zip_path)
        journal_path = path_for(zip_path)
        return nil unless ::File.exist?(journal_path)
        return nil unless ::File.exist?(zip_path)

        data = parse(::File.read(journal_path), journal_path)
        stat = ::File.stat(zip_path)
        unless stat.dev == data['device'] && stat.ino == data['inode']
          raise ::Zip::Error,
                "Revision journal #{journal_path} does not match the identity of #{zip_path}; " \
                'refusing to recover. The archive was probably replaced - remove the journal ' \
                'file by hand if it is stale.'
        end

        confirmed_length = data['confirmed_length']
        if stat.size < confirmed_length
          raise ::Zip::Error,
                "#{zip_path} is shorter (#{stat.size} bytes) than the confirmed length " \
                "(#{confirmed_length} bytes) recorded in #{journal_path}; cannot recover."
        end

        if data['state'] != 'complete' && stat.size > confirmed_length
          ::File.open(zip_path, 'r+b') do |file|
            file.truncate(confirmed_length)
            file.fsync
          end
        end

        ::File.delete(journal_path)
        data['state'] == 'complete' ? :complete : :rolled_back
      end

      def parse(content, journal_path = '(journal)')
        lines = content.split("\n")
        unless lines.first == FORMAT_VERSION
          raise ::Zip::Error, "Unrecognized revision journal format in #{journal_path}"
        end

        data = lines[1..].to_h { |line| line.split('=', 2) }
        %w[device inode confirmed_length state].each do |key|
          unless data[key]
            raise ::Zip::Error, "Corrupt revision journal #{journal_path}: missing #{key}"
          end
        end
        {
          'device'           => Integer(data['device'], 10),
          'inode'            => Integer(data['inode'], 10),
          'confirmed_length' => Integer(data['confirmed_length'], 10),
          'state'            => data['state']
        }
      rescue ArgumentError, TypeError
        raise ::Zip::Error, "Corrupt revision journal #{journal_path}"
      end
    end

    attr_reader :state

    def initialize(zip_path, data)
      @zip_path = zip_path
      @data = data
      @state = data['state']
    end

    # Records that the commit has reached +state+, durably. States must be
    # advanced in STATES order.
    def advance(state)
      index = STATES.index(state)
      raise ::Zip::Error, "Unknown revision journal state #{state.inspect}" if index.nil?

      if index <= STATES.index(@state)
        raise ::Zip::Error, 'Revision journal states must advance in order'
      end

      @data['state'] = state
      @state = state
      write
    end

    # Writes the current journal state and fsyncs it.
    def write
      lines = @data.map { |key, value| "#{key}=#{value}" }
      content = "#{([FORMAT_VERSION] + lines).join("\n")}\n"
      ::File.open(self.class.path_for(@zip_path), 'w') do |file|
        file.write(content)
        file.fsync
      end
    end

    # Removes the journal. Only called once the completion marker has been
    # written; a crash between the two is harmless (recovery sees the
    # +complete+ state and leaves the archive alone).
    def cleanup
      ::File.delete(self.class.path_for(@zip_path))
    end
  end
end
