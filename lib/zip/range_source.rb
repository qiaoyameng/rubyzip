# frozen_string_literal: true

module Zip
  # A RangeSource describes an immutable, randomly-readable byte object
  # (typically a large object in remote storage, such as an S3 object) from
  # which a zip archive can be parsed without downloading the whole object.
  #
  # The library never performs any HTTP requests itself. Instead, the caller
  # provides an object implementing this interface, and the library uses it
  # to issue small ranged reads for the end-of-central-directory record, the
  # central directory, a single local header and that entry's data only.
  #
  # A RangeSource must implement three methods:
  #
  # #size::
  #   Returns the total length of the object in bytes as an Integer.
  #
  # #identity::
  #   Returns a value (String, Integer, etc.) that uniquely identifies the
  #   exact version of the object being read. If the object is ever replaced
  #   or modified, the identity must change. The library captures the
  #   identity when the archive is opened and checks it before every read; a
  #   mismatch raises Zip::ObjectChangedError and aborts the current read, so
  #   bytes from two different versions of the object are never mixed.
  #
  # #read_at(offset, length)::
  #   Returns exactly +length+ bytes starting at +offset+ as a binary
  #   encoded String (Encoding::BINARY). Both arguments are non-negative
  #   Integers and +offset + length+ never exceeds #size: the library checks
  #   every range before requesting it. Returning fewer than +length+ bytes
  #   is treated as a corrupt/truncated object and raises
  #   Zip::ShortReadError.
  #
  # @example
  #   class S3RangeSource
  #     def initialize(client, bucket, key)
  #       @client, @bucket, @key = client, bucket, key
  #       head = @client.head_object(bucket: @bucket, key: @key)
  #       @size = head.content_length
  #       @identity = head.etag
  #     end
  #
  #     attr_reader :size, :identity
  #
  #     def read_at(offset, length)
  #       @client.get_object(
  #         bucket: @bucket,
  #         key: @key,
  #         range: "bytes=#{offset}-#{offset + length - 1}"
  #       ).body.read
  #     end
  #   end
  #
  #   Zip::File.open_from_range(source) do |zip_file|
  #     puts zip_file.read('only-this-member.txt')
  #   end
  module RangeSource
    # The total length of the backing object in bytes.
    #
    # @return [Integer]
    def size
      raise NotImplementedError, "#{self.class} must implement #size"
    end

    # A value uniquely identifying the exact immutable version of the
    # backing object.
    #
    # @return [Object]
    def identity
      raise NotImplementedError, "#{self.class} must implement #identity"
    end

    # Reads and returns exactly +length+ bytes beginning at +offset+, encoded
    # as ASCII-8BIT. Implementations should not return short reads: if fewer
    # bytes are returned, the library raises Zip::ShortReadError.
    #
    # @param offset [Integer] non-negative byte offset
    # @param length [Integer] number of bytes to read (positive)
    # @return [String]
    def read_at(_offset, _length)
      raise NotImplementedError, "#{self.class} must implement #read_at"
    end

    # A RangeSource backed by a String in memory. This implements exactly
    # the same protocol as a remote-backed source (all access goes through
    # #read_at), so it is useful for tests and as a reference
    # implementation. The byte ranges requested are recorded and can be
    # inspected to verify that only the expected parts of an archive are
    # touched (for example, that reading a small member never reads the
    # body of a different, large member).
    #
    # If +identity+ is not given, the object identity is +:fixed+; a new
    # identity can later be forced with #simulate_object_change! to emulate
    # the remote object being replaced underneath the reader.
    class InMemory
      include RangeSource

      # @return [Array<Array(Integer, Integer)>] the (offset, length) ranges
      #   that have been read so far, in request order.
      attr_reader :read_ranges

      # @param data [String] the full contents of the backing object
      # @param identity [Object] value identifying this version of the object
      def initialize(data, identity: :fixed)
        @data = data.to_s.dup.force_encoding(Encoding::BINARY)
        @identity = identity
        @read_ranges = []
      end

      # @return [Integer]
      def size
        @data.bytesize
      end

      # @return [Object]
      attr_reader :identity

      # Returns the exact requested slice. Raises Zip::ShortReadError if the
      # in-memory object is shorter than requested and IndexError if the
      # range itself is out of bounds (the library always checks ranges
      # first, so the latter is only reachable if the object shrinks).
      def read_at(offset, length)
        @read_ranges << [offset, length]
        slice = @data.byteslice(offset, length)
        raise Zip::ShortReadError.new(offset, length, slice&.bytesize || 0) if
          slice.nil? || slice.bytesize != length

        slice.dup.force_encoding(Encoding::BINARY)
      end

      # Replaces the object's contents as if the remote object had been
      # overwritten. The next read will observe the new identity, so any
      # archive opened against the old identity aborts with
      # Zip::ObjectChangedError. The record of ranges read against the old
      # version is preserved by default so it can still be inspected.
      #
      # @param new_data [String] the new contents
      # @param new_identity [Object] identity of the new version
      def simulate_object_change!(new_data, new_identity: :changed,
                                  reset_read_ranges: false)
        @data = new_data.to_s.dup.force_encoding(Encoding::BINARY)
        @identity = new_identity
        @read_ranges.clear if reset_read_ranges
      end

      # @return [Boolean] whether any read covered a byte in +range+
      def range_was_read?(range)
        @read_ranges.any? do |offset, length|
          ranges_overlap?(offset, length, range.begin, range.size)
        end
      end

      # @return [Boolean] the total number of bytes that have been read
      def bytes_read
        @read_ranges.sum(&:last)
      end

      private

      def ranges_overlap?(offset_a, length_a, offset_b, length_b)
        offset_a < offset_b + length_b && offset_b < offset_a + length_a
      end
    end
  end
end
