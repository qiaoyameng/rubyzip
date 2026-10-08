# frozen_string_literal: true

require_relative 'range_source'

module Zip
  # Reads a zip archive through a {RangeSource}, fetching only the bounded
  # pieces needed: a bounded slice of the tail (to locate the End of Central
  # Directory record), the central directory, and on demand the local header
  # and compressed data of the single entry being read.
  #
  # This class is internal; use {Zip::File.open_range}.
  #
  # @api private
  class RangeReader
    STATIC_EOCD_SIZE       = CentralDirectory::STATIC_EOCD_SIZE
    ZIP64_STATIC_EOCD_SIZE = CentralDirectory::ZIP64_STATIC_EOCD_SIZE
    ZIP64_EOCD_LOC_SIZE    = CentralDirectory::ZIP64_EOCD_LOC_SIZE
    # The initial tail read is bounded by the largest possible classic
    # End of Central Directory record (22 static bytes plus a 65535 byte
    # comment). The Zip64 records, which sit just before it, are only fetched
    # when the classic record signals they are required.
    MAX_TAIL_SIZE =
      CentralDirectory::MAX_FILE_COMMENT_SIZE + CentralDirectory::STATIC_EOCD_SIZE
    END_OF_CD_SIG          = CentralDirectory::END_OF_CD_SIG
    ZIP64_END_OF_CD_SIG    = CentralDirectory::ZIP64_END_OF_CD_SIG
    ZIP64_EOCD_LOCATOR_SIG = CentralDirectory::ZIP64_EOCD_LOCATOR_SIG
    LOCAL_ENTRY_SIGNATURE  = ::Zip::LOCAL_ENTRY_SIGNATURE
    LOCAL_ENTRY_STATIC_HEADER_LENGTH =
      ::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH
    CDIR_ENTRY_STATIC_HEADER_LENGTH =
      ::Zip::CDIR_ENTRY_STATIC_HEADER_LENGTH

    # @return [EntrySet] the entries parsed from the central directory
    attr_reader :entry_set

    # @return [String] the archive comment
    attr_reader :comment

    # @return [RangeSource::Session] the identity-checked range session
    attr_reader :session

    # Opens and parses the central directory of the object exposed by
    # `source`.
    #
    # @param source [RangeSource]
    # @api private
    def initialize(source)
      @session = RangeSource::Session.new(source)
      @entry_set = EntrySet.new
      @comment = ''
      read_central_directory
    end

    # Returns an IO positioned at the chosen entry's local header, bounded
    # so reading the entry's compressed data can never fetch bytes from
    # another entry. The local header is read eagerly (and validated); the
    # entry data itself is only fetched when the returned stream is read.
    # @api private
    def open_entry(entry, decrypter: nil)
      header_offset = validated_header_offset(entry)
      header_io, header = read_local_header(entry, header_offset)
      validate_entry_data!(entry, header_offset, header_io.tell, header.compressed_size)

      window = RangeSource::RangedIO.new(
        @session,
        base:  header_offset,
        limit: header_io.tell + header.compressed_size
      )
      InputStream.new(window).tap do |zis|
        zis.instance_variable_set(:@decrypter, decrypter)
        zis.instance_variable_set(:@complete_entry, entry)
        zis.get_next_entry
      end
    end

    private

    def validated_header_offset(entry)
      offset = header_offset_for(entry)
      return offset if offset.kind_of?(Integer) && offset >= 0 && offset < @session.size

      raise Zip::Error,
            "Invalid local header offset (#{offset.inspect}) for entry '#{entry.name}'"
    end

    # Read the static local header to discover the name and extra field
    # lengths, then parse the whole header (static header + name + extra
    # field) so the entry's own (possibly Zip64) sizes are known.
    def read_local_header(entry, header_offset)
      static_bytes = @session.read_exact(
        header_offset, LOCAL_ENTRY_STATIC_HEADER_LENGTH
      )
      unless static_bytes.unpack1('V') == LOCAL_ENTRY_SIGNATURE
        raise Error,
              "Zip local header magic not found for entry '#{entry.name}' " \
              "at offset #{header_offset}"
      end

      name_length, extra_length = static_bytes.unpack('@26vv')
      header_length = LOCAL_ENTRY_STATIC_HEADER_LENGTH + name_length + extra_length
      if header_offset + header_length > @session.size
        raise Error, "Local header for entry '#{entry.name}' extends past the object"
      end

      header_io = RangeSource::RangedIO.new(
        @session, base: header_offset, limit: header_length
      )
      header = Entry.read_local_entry(header_io)
      raise Error, "Could not read local header for entry '#{entry.name}'" if header.nil?

      [header_io, header]
    end

    def validate_entry_data!(entry, header_offset, header_length, compressed_size)
      unless compressed_size.kind_of?(Integer) && compressed_size >= 0
        raise Error, "Invalid compressed size for entry '#{entry.name}'"
      end
      return if header_offset + header_length + compressed_size <= @session.size

      raise Error, "Entry '#{entry.name}' data extends past the end of the object"
    end

    def header_offset_for(entry)
      if entry.zip64? && entry.extra[:zip64].relative_header_offset
        return entry.extra[:zip64].relative_header_offset
      end

      entry.local_header_offset
    end

    # 1. Read a bounded tail slice. 2. Locate and parse the EOCD (and the
    # Zip64 records if present). 3. Read exactly the central directory range
    # and parse the entries out of it, never seeking to local headers.
    def read_central_directory
      base, tail = read_tail
      cdir_offset, cdir_size, size, @comment = parse_eocd(tail, base)

      validate_central_directory!(cdir_offset, cdir_size, size)

      cdir_bytes = @session.read_exact(cdir_offset, cdir_size)
      parse_entries(StringIO.new(cdir_bytes), size)
    end

    def read_tail
      # `size` is an Integer, so `zero?` is correct here (there is no
      # `empty?`); Rubocop's ZeroLengthPredicate cop does not know that.
      # rubocop:disable Style/ZeroLengthPredicate
      raise Error, 'Cannot read central directory from an empty object' if @session.size.zero?
      # rubocop:enable Style/ZeroLengthPredicate

      length = [MAX_TAIL_SIZE, @session.size].min
      base = @session.size - length
      [base, @session.read_exact(base, length)]
    end

    # Returns [cdir_offset, cdir_size, entry_count, comment].
    def parse_eocd(tail, base)
      position = CentralDirectory.new.send(:locate_e_o_c_d, tail)
      raise Error, 'Zip end of central directory signature not found' unless position

      absolute_eocd_position = base + position
      eocd = tail.slice(position..-1)
      _, disk, start_disk, disk_entries, size, cdir_size, cdir_offset,
      comment_length = eocd.unpack('VvvvvVVv')

      complete = !(disk == 0xFFFF || start_disk == 0xFFFF ||
                   disk_entries == 0xFFFF || size == 0xFFFF ||
                   cdir_size == 0xFFFFFFFF || cdir_offset == 0xFFFFFFFF)
      if complete && disk_entries != size
        raise Error, 'Entry count mismatch in end of central directory record'
      end

      comment = eocd.slice(STATIC_EOCD_SIZE, comment_length) || ''
      raise Error, 'Truncated end of central directory record' if comment.bytesize != comment_length

      if complete
        reject_multi_disk!(disk: disk, start_disk: start_disk)
        return [cdir_offset, cdir_size, size, comment]
      end

      parse_zip64_eocd(tail, base, absolute_eocd_position, comment)
    end

    def parse_zip64_eocd(tail, base, absolute_eocd_position, comment)
      # The classic EOCD says a Zip64 record is needed. The locator sits
      # immediately before the classic record in the standard layout; fetch
      # it (and the bytes preceding it that may already be in the buffered
      # tail) before reading the Zip64 EOCD it points at.
      locator = read_zip64_locator(tail, base, absolute_eocd_position)
      _, locator_disk, zip64_eocd_offset, total_disks = locator.unpack('VVQ<V')
      reject_multi_disk!(disk: locator_disk, total_disks: total_disks)

      zip64_eocd_offset = nonneg_offset!(zip64_eocd_offset)
      zip64_bytes = @session.read_exact(zip64_eocd_offset, ZIP64_STATIC_EOCD_SIZE)
      signature, _record_size, _made_by, _needed, disk, start_disk,
        disk_entries, size, cdir_size, cdir_offset =
        zip64_bytes.unpack('VQ<vvVVQ<Q<Q<Q<')

      unless signature == ZIP64_END_OF_CD_SIG
        raise Error, 'Zip64 end of central directory signature not found'
      end

      reject_multi_disk!(disk: disk, start_disk: start_disk, total_disks: total_disks)
      if disk_entries != size
        raise Error,
              "Zip64 entry count mismatch (#{disk_entries} on disk, #{size} total)"
      end

      [cdir_offset, cdir_size, size, comment]
    end

    # Returns the 20-byte Zip64 EOCD locator. It is first sought in the
    # buffered tail (including at its fixed position immediately before the
    # classic EOCD); otherwise it is fetched directly.
    def read_zip64_locator(tail, base, absolute_eocd_position)
      fixed_absolute = absolute_eocd_position - ZIP64_EOCD_LOC_SIZE
      if fixed_absolute >= base
        fixed = fixed_absolute - base
        candidate = tail.slice(fixed, ZIP64_EOCD_LOC_SIZE)
        if candidate && candidate.bytesize == ZIP64_EOCD_LOC_SIZE &&
           candidate.unpack1('V') == ZIP64_EOCD_LOCATOR_SIG
          return candidate
        end
      end

      if fixed_absolute >= 0
        candidate = @session.read_exact(fixed_absolute, ZIP64_EOCD_LOC_SIZE)
        return candidate if candidate.unpack1('V') == ZIP64_EOCD_LOCATOR_SIG
      end

      # Fallback: scan the buffered tail for a locator, as the shared IO
      # reader does, to tolerate unusual layouts.
      relative_position =
        CentralDirectory.new.send(
          :locate_zip64_eocd_locator, tail, absolute_eocd_position - base
        )
      if relative_position
        candidate = tail.slice(relative_position, ZIP64_EOCD_LOC_SIZE)
        if candidate && candidate.bytesize == ZIP64_EOCD_LOC_SIZE &&
           candidate.unpack1('V') == ZIP64_EOCD_LOCATOR_SIG
          return candidate
        end
      end

      raise Error, 'Zip64 end of central directory locator signature expected but not found'
    end

    def nonneg_offset!(offset)
      return offset if offset.kind_of?(Integer) && offset >= 0 && offset < @session.size

      raise Error, "Invalid Zip64 end of central directory offset: #{offset.inspect}"
    end

    def reject_multi_disk!(disk: nil, start_disk: nil, total_disks: nil)
      raise SplitArchiveError, 'Multi-disk (split) archives are not supported' if
        (total_disks && total_disks != 1) ||
        (disk && disk != 0) ||
        (start_disk && start_disk != 0)
    end

    def validate_central_directory!(offset, size, count)
      unless offset.kind_of?(Integer) && size.kind_of?(Integer) && count.kind_of?(Integer) &&
             offset >= 0 && size >= 0 && count >= 0
        raise Error, 'Invalid central directory offset or size in end record'
      end
      raise Error, 'Central directory starts past the end of the object' if offset > @session.size
      if offset + size > @session.size
        raise Error, 'Central directory extends past the end of the object'
      end
      return unless count * CDIR_ENTRY_STATIC_HEADER_LENGTH > size

      error = EntryNumberMismatchError.new(count, size)
      raise error if Zip.validate_declared_number_of_entries

      warn error.message
    end

    # Parses entries sequentially from an in-memory copy of the central
    # directory. Local headers are deliberately *not* read here: doing so
    # would fetch data of entries the caller never asks for.
    def parse_entries(io, expected_count)
      parsed = 0
      expected_count.times do
        entry = Entry.read_c_dir_entry(io)
        break if entry.nil?

        @entry_set << entry
        parsed += 1
      end
      return unless parsed != expected_count

      raise Error,
            "Expected #{expected_count} central directory entries but found #{parsed}"
    end
  end
end
