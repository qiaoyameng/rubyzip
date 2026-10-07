# frozen_string_literal: true

module Zip
  # A RevisionReceipt describes one committed revision of a zip archive:
  # exactly where its central directory and end-of-central-directory record
  # sit inside the file. Receipts are returned by
  # Zip::File#commit_append_revision and Zip::File#current_revision, and can
  # be passed back to Zip::File.open via the +revision:+ keyword to read the
  # archive exactly as it looked at that revision, even after later
  # revisions have been appended.
  #
  # Receipts are plain value objects; use #to_h and ::from_h to persist
  # them (as JSON, YAML, Marshal, ...) across processes.
  #
  # A receipt is only valid for as long as the bytes it points at are left
  # untouched. A full (non-append) Zip::File#commit rewrites the whole
  # archive and therefore invalidates every earlier receipt, as does any
  # external modification of the file.
  class RevisionReceipt
    # The path of the archive this receipt was issued for (informational).
    attr_reader :path

    # Byte offset at which this revision's central directory starts.
    attr_reader :cdir_offset

    # Size in bytes of this revision's central directory.
    attr_reader :cdir_size

    # Number of entries in this revision's central directory.
    attr_reader :entry_count

    # Byte offset of this revision's end-of-central-directory record.
    attr_reader :eocd_offset

    # Byte offset one past the end of this revision (the file size that was
    # confirmed when the revision completed).
    attr_reader :end_offset

    # The archive comment of this revision.
    attr_reader :comment

    def initialize(path:, cdir_offset:, cdir_size:, entry_count:, eocd_offset:,
                   end_offset:, comment: '')
      @path        = path
      @cdir_offset = cdir_offset
      @cdir_size   = cdir_size
      @entry_count = entry_count
      @eocd_offset = eocd_offset
      @end_offset  = end_offset
      @comment     = comment
    end

    # Returns a Hash with Symbol keys suitable for serialization.
    def to_h
      {
        path:        @path,
        cdir_offset: @cdir_offset,
        cdir_size:   @cdir_size,
        entry_count: @entry_count,
        eocd_offset: @eocd_offset,
        end_offset:  @end_offset,
        comment:     @comment
      }
    end

    # Rebuilds a receipt from a Hash as produced by #to_h. Accepts Symbol
    # or String keys.
    def self.from_h(hash)
      new(**hash.transform_keys(&:to_sym))
    end

    def ==(other)
      other.kind_of?(RevisionReceipt) && to_h == other.to_h
    end
  end
end
