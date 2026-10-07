# frozen_string_literal: true

module Zip
  # RevisionAppender performs Zip::File's append-revision commit. Instead
  # of rewriting the whole archive like Zip::File#commit does, it appends
  # to the existing file, in this exact order:
  #
  # 1. +body+       - the local headers and data of the entries that were
  #                   added, replaced or renamed. Unchanged entries are not
  #                   touched at all: their central directory records in
  #                   the new revision keep pointing at their original
  #                   local records.
  # 2. +directory+  - a fresh central directory covering every entry in
  #                   the new revision.
  # 3. +end_record+ - the (Zip64, if needed) end-of-central-directory
  #                   records.
  # 4. +receipt+    - the completion marker in the revision journal. The
  #                   commit is only considered successful once this marker
  #                   is durably written; see Zip::RevisionJournal.
  #
  # Each stage is fsync'd and journaled before the next begins, so a crash
  # at any point can be rolled back to the last confirmed length by
  # Zip::File.recover_append_revision.
  class RevisionAppender # :nodoc:all
    # Stage names passed to the optional stage hook, in commit order.
    STAGES = [:body, :directory, :end_record, :receipt].freeze

    def initialize(zip_path, cdir, suppress_extra_fields: false, stage_hook: nil)
      @zip_path = zip_path
      @cdir = cdir
      @suppress_extra_fields = suppress_extra_fields
      @stage_hook = stage_hook
    end

    # Appends the new revision and returns its RevisionReceipt. If an
    # exception is raised (including one injected via the stage hook), the
    # journal is left in place so the partial revision can be rolled back
    # by Zip::File.recover_append_revision.
    def commit
      confirmed_length = ::File.size(@zip_path)
      journal = RevisionJournal.start(@zip_path, confirmed_length)
      receipt = append_revision(journal, confirmed_length)

      # The completion marker: only after this is durably written may the
      # commit report success.
      journal.advance('complete')
      run_hook(:receipt, nil)
      journal.cleanup
      receipt
    end

    private

    def append_revision(journal, confirmed_length)
      receipt = nil
      ::File.open(@zip_path, 'r+b') do |io|
        unless io.size == confirmed_length
          raise ::Zip::Error, "#{@zip_path} changed on disk while the revision was being prepared"
        end

        io.seek(0, IO::SEEK_END)
        run_stage(journal, :body, io) { write_changed_entry_bodies(io) }

        cdir_offset = cdir_size = nil
        run_stage(journal, :directory, io) do
          cdir_offset, cdir_size = @cdir.write_c_dir_entries(
            io, suppress_extra_fields: @suppress_extra_fields
          )
        end

        eocd_offset = nil
        run_stage(journal, :end_record, io) do
          eocd_offset = @cdir.write_end_records(io, cdir_offset, cdir_size)
        end

        receipt = RevisionReceipt.new(
          path:        @zip_path,
          cdir_offset: cdir_offset,
          cdir_size:   cdir_size,
          entry_count: @cdir.size,
          eocd_offset: eocd_offset,
          end_offset:  io.pos,
          comment:     @cdir.comment
        )
      end
      receipt
    end

    # Writes the bytes for one stage, fsyncs them, and only then records
    # the stage in the journal.
    def run_stage(journal, stage, io)
      yield
      io.fsync
      journal.advance(stage.to_s)
      run_hook(stage, io)
    end

    def run_hook(stage, io)
      @stage_hook&.call(stage, io)
    end

    # Writes the local header and data of every entry that changed since
    # the archive was opened. Unchanged entries are neither read nor
    # rewritten - the new central directory simply keeps referencing their
    # existing local records.
    def write_changed_entry_bodies(io)
      zos = ::Zip::OutputStream.new(io,
                                    stream:                true,
                                    suppress_extra_fields: @suppress_extra_fields)
      # OutputStream rewinds its stream on open; the revision body belongs
      # at the end of the archive.
      io.seek(0, IO::SEEK_END)
      @cdir.each do |entry|
        next unless entry.dirty?

        entry.write_to_zip_output_stream(zos)
        entry.clean_up
      end
      zos.finish_entries
    end
  end
end
