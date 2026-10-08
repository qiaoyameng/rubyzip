# frozen_string_literal: true

require 'forwardable'

require_relative 'dirtyable'

module Zip
  class CentralDirectory # :nodoc:
    extend Forwardable
    include Dirtyable

    END_OF_CD_SIG          = 0x06054b50
    ZIP64_END_OF_CD_SIG    = 0x06064b50
    ZIP64_EOCD_LOCATOR_SIG = 0x07064b50

    STATIC_EOCD_SIZE       = 22
    ZIP64_STATIC_EOCD_SIZE = 56
    ZIP64_EOCD_LOC_SIZE    = 20
    MAX_FILE_COMMENT_SIZE  = (1 << 16) - 1
    MAX_END_OF_CD_SIZE     =
      MAX_FILE_COMMENT_SIZE + STATIC_EOCD_SIZE + ZIP64_EOCD_LOC_SIZE

    attr_accessor :comment

    def_delegators :@entry_set,
                   :<<, :delete, :each, :entries, :find_entry, :glob,
                   :include?, :size

    mark_dirty :<<, :comment=, :delete

    def initialize(entries = EntrySet.new, comment = '') # :nodoc:
      super(dirty_on_create: false)
      @entry_set = entries.kind_of?(EntrySet) ? entries : EntrySet.new(entries)
      @comment   = comment
    end

    def read_from_stream(io)
      read_eocds(io)
      read_central_directory_entries(io)
    end

    # Reads the central directory from a randomly-readable source (a
    # Zip::RangeSource, via a RangeIO). Only the bounded end-of-central
    # directory area, the central directory itself and the small local
    # headers of the entries are read; entry data is never touched.
    def read_from_range(io)
      read_eocds(io, total_size: io.total_size)
      read_central_directory_entries(io)
    end

    def write_to_stream(io, suppress_extra_fields: false) # :nodoc:
      cdir_offset = io.tell
      @entry_set.each do |entry|
        entry.write_c_dir_entry(io, suppress_extra_fields: suppress_extra_fields)
      end
      eocd_offset = io.tell
      cdir_size = eocd_offset - cdir_offset
      if Zip.write_zip64_support &&
         (cdir_offset > 0xFFFFFFFF || cdir_size > 0xFFFFFFFF || @entry_set.size > 0xFFFF)
        write_64_e_o_c_d(io, cdir_offset, cdir_size)
        write_64_eocd_locator(io, eocd_offset)
      end
      write_e_o_c_d(io, cdir_offset, cdir_size)
    end

    # Reads the End of Central Directory Record (and the Zip64 equivalent if
    # needs be) and returns the number of entries in the archive. This is a
    # convenience method that avoids reading in all of the entry data to get a
    # very quick entry count.
    def count_entries(io)
      read_eocds(io)
      @size
    end

    # As #count_entries, but for a Zip::RangeSource-backed IO.
    def count_entries_from_range(io)
      read_eocds(io, total_size: io.total_size)
      @size
    end

    def ==(other) # :nodoc:
      return false unless other.kind_of?(CentralDirectory)

      @entry_set.entries.sort == other.entries.sort && comment == other.comment
    end

    private

    def write_e_o_c_d(io, offset, cdir_size) # :nodoc:
      tmp = [
        END_OF_CD_SIG,
        0, # @numberOfThisDisk
        0, # @numberOfDiskWithStartOfCDir
        @entry_set ? [@entry_set.size, 0xFFFF].min : 0,
        @entry_set ? [@entry_set.size, 0xFFFF].min : 0,
        [cdir_size, 0xFFFFFFFF].min,
        [offset, 0xFFFFFFFF].min,
        @comment ? @comment.bytesize : 0
      ]
      io << tmp.pack('VvvvvVVv')
      io << @comment
    end

    def write_64_e_o_c_d(io, offset, cdir_size) # :nodoc:
      tmp = [
        ZIP64_END_OF_CD_SIG,
        44, # size of zip64 end of central directory record (excludes signature and field itself)
        VERSION_MADE_BY,
        VERSION_NEEDED_TO_EXTRACT_ZIP64,
        0, # @numberOfThisDisk
        0, # @numberOfDiskWithStartOfCDir
        @entry_set ? @entry_set.size : 0, # number of entries on this disk
        @entry_set ? @entry_set.size : 0, # number of entries total
        cdir_size, # size of central directory
        offset # offset of start of central directory in its disk
      ]
      io << tmp.pack('VQ<vvVVQ<Q<Q<Q<')
    end

    def write_64_eocd_locator(io, zip64_eocd_offset)
      tmp = [
        ZIP64_EOCD_LOCATOR_SIG,
        0, # number of disk containing the start of zip64 eocd record
        zip64_eocd_offset, # offset of the start of zip64 eocd record in its disk
        1 # total number of disks
      ]
      io << tmp.pack('VVQ<V')
    end

    def unpack_64_e_o_c_d(buffer) # :nodoc:
      _, # ZIP64_END_OF_CD_SIG. We know we have this at this point.
      size_of_zip64_e_o_c_d,
      _version_made_by,
      _version_needed_for_extract,
      _number_of_this_disk,
      _number_of_disk_with_start_of_cdir,
      _total_number_of_entries_in_cdir_on_this_disk,
      @size,
      size_in_bytes,
      @cdir_offset = buffer.unpack('VQ<vvVVQ<Q<Q<Q<')

      validate_size!(@size, size_in_bytes)

      zip64_extensible_data_size =
        size_of_zip64_e_o_c_d - ZIP64_STATIC_EOCD_SIZE + 12
      @zip64_extensible_data = if zip64_extensible_data_size.zero?
                                 ''
                               else
                                 buffer.slice(
                                   ZIP64_STATIC_EOCD_SIZE,
                                   zip64_extensible_data_size
                                 )
                               end
    end

    def unpack_64_eocd_locator(buffer) # :nodoc:
      _, # ZIP64_EOCD_LOCATOR_SIG. We know we have this at this point.
      _, zip64_eocd_offset, = buffer.unpack('VVQ<V')

      zip64_eocd_offset
    end

    # Unpack the EOCD and return a boolean indicating whether this header is
    # complete without needing Zip64 extensions.
    def unpack_e_o_c_d(buffer) # :nodoc:
      _, # END_OF_CD_SIG. We know we have this at this point.
      number_of_this_disk,
      number_of_disk_with_start_of_cdir,
      total_number_of_entries_in_cdir_on_this_disk,
      @size,
      size_in_bytes,
      @cdir_offset,
      comment_length = buffer.unpack('VvvvvVVv')

      complete = !([number_of_this_disk, number_of_disk_with_start_of_cdir,
                    total_number_of_entries_in_cdir_on_this_disk, @size].any?(0xFFFF) ||
                    size_in_bytes == 0xFFFFFFFF || @cdir_offset == 0xFFFFFFFF)

      validate_size!(@size, size_in_bytes) if complete

      @comment = if comment_length.positive?
                   buffer.slice(STATIC_EOCD_SIZE, comment_length)
                 else
                   ''
                 end

      complete
    end

    def read_central_directory_entries(io) # :nodoc:
      # `StringIO` doesn't raise `EINVAL` if you seek beyond the current end,
      # so we need to catch that *and* query `io#eof?` here.
      eof = false
      begin
        io.seek(@cdir_offset, IO::SEEK_SET)
      rescue Errno::EINVAL
        eof = true
      end
      if eof || io.eof? ||
         (io.respond_to?(:total_size) &&
          @cdir_offset + CDIR_ENTRY_STATIC_HEADER_LENGTH > io.total_size)
        raise Error, 'Zip central directory offset is invalid or past the end of the file'
      end

      @entry_set = EntrySet.new
      @size.times do
        entry = Entry.read_c_dir_entry(io)
        break unless entry

        offset = if entry.zip64?
                   entry.extra[:zip64].relative_header_offset
                 else
                   entry.local_header_offset
                 end

        unless offset.nil?
          io_save = io.tell
          io.seek(offset, IO::SEEK_SET)
          entry.read_extra_field(read_local_extra_field(io), local: true)
          io.seek(io_save, IO::SEEK_SET)
        end

        @entry_set << entry
      end
    end

    def read_local_extra_field(io)
      buf = io.read(::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH) || ''
      return '' unless buf.bytesize == ::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH

      head, _, _, _, _, _, _, _, _, _, n_len, e_len = buf.unpack('VCCvvvvVVVvv')
      return '' unless head == ::Zip::LOCAL_ENTRY_SIGNATURE

      io.seek(n_len, IO::SEEK_CUR) # Skip over the entry name.
      io.read(e_len)
    end

    def read_eocds(io, total_size: nil) # :nodoc:
      base_location, data = eocd_data(io, total_size)

      # Locate the real End of Central Directory record by scanning the tail
      # forwards and taking the first signature whose declared comment runs
      # exactly to the end of the object. A forged signature placed inside a
      # file comment (or anywhere else before the real record) cannot win,
      # because the real record always appears first among records that
      # reach the end of the file. Scanning backwards with rindex would pick
      # the forged one whenever it follows the real signature.
      eocd_location = locate_eocd(data, total_size, base_location)

      # Parse the EOCD and return if it is complete without Zip64 extensions.
      return if unpack_e_o_c_d(data.slice(eocd_location..-1))

      # Need to read in the Zip64 EOCD locator and then the Zip64 EOCD.
      zip64_eocd_locator = data.rindex([ZIP64_EOCD_LOCATOR_SIG].pack('V'), eocd_location)
      unless zip64_eocd_locator
        raise Error, 'Zip64 end of central directory locator signature expected but not found'
      end

      # Do we already have the Zip64 EOCD in the data we've read?
      zip64_eocd_location = data.rindex([ZIP64_END_OF_CD_SIG].pack('V'), zip64_eocd_locator)

      zip64_eocd_data =
        if zip64_eocd_location
          # Yes.
          data.slice(zip64_eocd_location..zip64_eocd_locator)
        else
          # No. Read its location from the locator and then read it in.
          zip64_eocd_location = unpack_64_eocd_locator(
            data.slice(zip64_eocd_locator..eocd_location)
          )
          unless zip64_eocd_location
            raise Error, 'Zip64 end of central directory signature not found'
          end

          read_zip64_eocd(io, zip64_eocd_location,
                          base_location + zip64_eocd_locator, total_size)
        end

      # Finally, unpack the Zip64 EOCD.
      unpack_64_e_o_c_d(zip64_eocd_data)
    end

    def locate_eocd(data, total_size, base_location)
      signature = [END_OF_CD_SIG].pack('V')
      search_from = 0
      object_end = total_size || (base_location + data.bytesize)

      while (location = data.index(signature, search_from))
        return location if eocd_reaches_end?(data, location, base_location, object_end)

        search_from = location + signature.bytesize
      end

      raise Error, 'Zip end of central directory signature not found'
    end

    # True when the signature at +location+ is the complete static EOCD
    # header and its declared comment runs exactly to the end of the object.
    def eocd_reaches_end?(data, location, base_location, object_end)
      return false if location + STATIC_EOCD_SIZE > data.bytesize

      comment_length = data.slice(location + STATIC_EOCD_SIZE - 2, 2).unpack1('v')
      base_location + location + STATIC_EOCD_SIZE + comment_length == object_end
    end

    def read_zip64_eocd(io, offset, end_offset, total_size)
      length = end_offset - offset
      if total_size
        # Range-backed IO: validate the parsed offset strictly against the
        # object before issuing the read.
        validate_zip64_eocd_range!(offset, length, total_size)
      end
      io.seek(offset, IO::SEEK_SET)
      io.read(length)
    end

    def validate_zip64_eocd_range!(offset, length, total_size)
      valid = offset.kind_of?(Integer) && length.kind_of?(Integer) &&
              !offset.negative? && !length.negative? &&
              offset + length <= total_size
      return if valid

      raise InvalidRangeError,
            'invalid Zip64 end of central directory location ' \
            "(offset #{offset}, length #{length}, object size #{total_size})"
    end

    def eocd_data(io, total_size = nil)
      if total_size
        # Random-access source: read a bounded tail only, capped by the
        # object's known length. The tail never exceeds MAX_END_OF_CD_SIZE.
        raise Error, 'Zip end of central directory signature not found' if total_size.zero?

        base_location = [0, total_size - MAX_END_OF_CD_SIZE].max
        io.seek(base_location, IO::SEEK_SET)
        return [base_location, io.read(total_size - base_location)]
      end

      begin
        io.seek(-MAX_END_OF_CD_SIZE, IO::SEEK_END)
      rescue Errno::EINVAL
        io.seek(0, IO::SEEK_SET)
      end

      [io.tell, io.read]
    end

    def validate_size!(size, size_in_bytes)
      return if size * CDIR_ENTRY_STATIC_HEADER_LENGTH <= size_in_bytes

      error = EntryNumberMismatchError.new(size, size_in_bytes)
      raise error if Zip.validate_declared_number_of_entries

      warn error.message
    end
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
