# frozen_string_literal: true

require_relative 'central_directory'

module Zip
  # A RangeSource describes a remote (or otherwise non-seekable) object that
  # holds a zip archive and can only be read in bounded byte ranges. This
  # allows a single entry of a very large zip (for example, one stored in an
  # object store and addressed over HTTP) to be read without downloading the
  # whole archive: only the end of the object, the central directory, and the
  # chosen entry's local header and data are fetched.
  #
  # Rubyzip never makes any network requests itself. The caller provides an
  # object that implements this protocol and is responsible for translating
  # range requests into whatever transport is in use (HTTP Range requests,
  # for instance). An object only needs to respond to the three methods
  # below; it does not need to include or extend this module.
  #
  # - `size` returns the total size of the object in bytes as an Integer.
  # - `identity` returns a value that uniquely identifies the current
  #   version of the object's content (an ETag, a version id, a content
  #   hash, ...). If the object changes, this value must change too. It is
  #   re-checked before every range read that misses the cache; a change
  #   causes all cached bytes to be discarded and the in-flight read to be
  #   aborted with an {ObjectChangedError}, so bytes from two versions of
  #   the object are never mixed.
  # - `read_at(offset, length)` returns a binary String containing exactly
  #   `length` bytes starting at absolute byte `offset`. The range is
  #   guaranteed to lie entirely within the object (every range is validated
  #   against `size` before this method is called), so returning fewer bytes
  #   is treated as a transport error and raises {ShortReadError}.
  #
  # Example:
  #
  #   class HttpRangeSource
  #     def initialize(uri)
  #       @uri = uri
  #       response = http_head(uri)
  #       @size     = response.content_length
  #       @identity = response['ETag']
  #     end
  #
  #     attr_reader :size, :identity
  #
  #     def read_at(offset, length)
  #       http_get_range(@uri, offset, offset + length - 1).body
  #     end
  #   end
  #
  #   Zip::File.open_range(HttpRangeSource.new('https://example.com/a.zip')) do |zip|
  #     puts zip.read('wanted.txt') # other entries' data is never downloaded
  #   end
  module RangeSource
    # A minimal IO-like view over a RangeSource. It supports just the
    # methods ({#seek}, {#tell}, {#read}, {#eof?} and {#close}) that the zip
    # parsing code needs. All byte fetching goes through a shared {Session},
    # which validates ranges, enforces object identity and bounds the cache.
    #
    # A view may be restricted to `limit` bytes starting at `base`; reads
    # past the window report EOF, so a view used to read one entry's
    # compressed data can never pull in bytes belonging to another entry.
    #
    # @api private
    class RangedIO
      # @param session [Session] the shared, identity-checked session
      # @param base [Integer] absolute offset where the view starts
      # @param limit [Integer, nil] maximum readable bytes (nil = to the end)
      # @api private
      def initialize(session, base: 0, limit: nil)
        @session = session
        @base = base
        @limit = limit
        @pos = 0
        @closed = false
      end

      # Returns the current read position relative to the start of the view.
      # @return [Integer]
      # @api private
      def tell
        @pos
      end

      # Moves the read position. Seeking never fetches data.
      # @api private
      def seek(amount, whence = IO::SEEK_SET)
        raise IOError, 'closed stream' if @closed

        @pos =
          case whence
          when IO::SEEK_SET then amount
          when IO::SEEK_CUR then @pos + amount
          when IO::SEEK_END then (end_offset - @base) + amount
          else raise ArgumentError, "invalid whence #{whence}"
          end
        raise Errno::EINVAL, 'Invalid argument - invalid seek position' unless @pos >= 0

        0
      end

      # Returns true when the view is positioned at, or past, its end.
      # @api private
      def eof?
        remaining <= 0
      end

      alias eof eof? # :nodoc:

      # Reads up to `length` bytes from the view. With no argument, reads the
      # remainder of the bounded view.
      # @api private
      def read(length = nil)
        raise IOError, 'closed stream' if @closed

        length = remaining if length.nil?
        return +''.b if length.zero?
        return nil if eof?

        length = [length, remaining].min
        data = @session.read_exact(@base + @pos, length)
        @pos += data.bytesize
        data
      end

      # Closes the view. The underlying session and shared cache are left
      # untouched; only this view becomes unusable.
      # @api private
      def close
        @closed = true
        nil
      end

      # Duplicates the view with an independent position, sharing the
      # session (and therefore the bounded cache and object identity).
      # @api private
      def initialize_copy(other)
        super
        @session = other.instance_variable_get(:@session)
        @base = other.instance_variable_get(:@base)
        @limit = other.instance_variable_get(:@limit)
        @pos = 0
        @closed = false
      end

      private

      # Absolute offset (relative to the object start) of the end of the view.
      def end_offset
        @base + (@limit || (@session.size - @base))
      end

      def remaining
        end_offset - (@base + @pos)
      end
    end

    # A Session performs and caches validated range reads against one fixed
    # version of a RangeSource's object. It is internal to the ranged reader;
    # callers do not use it directly.
    #
    # @api private
    class Session
      # Maximum number of distinct ranges kept cached. Entries are evicted
      # least-recently-used, so the cache stays bounded however many ranges
      # are read.
      MAX_CACHE_ENTRIES = 32

      attr_reader :size # :nodoc:

      # @param source [RangeSource]
      # @api private
      def initialize(source)
        unless source.respond_to?(:size) && source.respond_to?(:identity) &&
               source.respond_to?(:read_at)
          raise ArgumentError,
                'a range source must respond to #size, #identity and #read_at'
        end

        @source = source
        @size = nonnegative_integer(source.size, 'size')
        @identity = source.identity
        @cache = {}
      end

      # Fetches exactly `length` bytes at absolute `offset`, validating the
      # range against the object size first and re-checking object identity
      # on any cache miss.
      # @api private
      def read_exact(offset, length)
        offset = range_integer(offset, 'offset')
        length = range_integer(length, 'length')
        raise Zip::RangeError.new(offset, length, @size) if length > @size - offset
        return +''.b if length.zero?

        key = [offset, length]
        if (cached = @cache[key])
          # Refresh LRU order: a hit becomes the most recently used entry.
          @cache.delete(key)
          @cache[key] = cached
          return cached.dup
        end

        check_identity!
        data = @source.read_at(offset, length)
        unless data.kind_of?(String) && data.bytesize == length
          received = data.kind_of?(String) ? data.bytesize : 0
          raise Zip::ShortReadError.new(offset, length, received)
        end

        data = data.b.freeze
        remember(key, data)
        data.dup
      end

      # Re-checks object identity, raising if it changed and discarding every
      # cached byte.
      # @api private
      def check_identity!
        current = @source.identity
        return if current == @identity

        @cache.clear
        raise Zip::ObjectChangedError.new(@identity, current)
      end

      private

      def remember(key, data)
        @cache.delete(key)
        @cache[key] = data
        evict while @cache.size > MAX_CACHE_ENTRIES
      end

      def evict
        @cache.delete(@cache.first&.first)
      end

      def nonnegative_integer(value, name)
        return value if value.kind_of?(Integer) && value >= 0

        raise ArgumentError, "#{name} must be a non-negative Integer"
      end

      # As {#nonnegative_integer}, but an actually-negative Integer is a
      # requested range that would run backwards: that is a RangeError, not
      # an argument type error.
      def range_integer(value, name)
        return value if value.kind_of?(Integer) && value >= 0

        raise ArgumentError, "#{name} must be a non-negative Integer" unless value.kind_of?(Integer)

        raise Zip::RangeError.new(value, nil, @size) if name == 'offset'

        raise Zip::RangeError.new(nil, value, @size)
      end
    end
  end
end
