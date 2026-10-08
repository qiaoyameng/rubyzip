# frozen_string_literal: true

require_relative 'range_source'

module Zip
  # Presents a seekable, readable IO interface over a Zip::RangeSource.
  #
  # This lets the existing zip parsing code, which speaks `seek`/`read`, be
  # reused unchanged against an object that only supports random ranged
  # reads. Every byte range is validated against the object's length before
  # it is requested, and the source identity is checked before every fetch
  # so a replaced object can never be mixed with the archive currently being
  # parsed.
  #
  # A small, sparse-safe cache coalesces identical repeated requests (for
  # example, a local header read twice through duplicated IOs). A fetch
  # never extends beyond the exact range that was requested, so caching can
  # never pull in bytes from an unrelated part of the object (such as
  # another entry's data). The cache is bound to the identity the archive
  # was opened with and is discarded immediately if that changes.
  #
  # @api private
  class RangeIO
    # Number of fetched ranges kept in the cache.
    DEFAULT_CACHE_SIZE = 8

    def initialize(source, cache_size: DEFAULT_CACHE_SIZE)
      @source = source
      @total_size = check_integer(source.size, 'size')
      raise InvalidRangeError, 'size must be non-negative' if @total_size.negative?

      @identity = source.identity
      @pos = 0
      @closed = false
      @cache = {}
      @cache_order = []
      @max_cached = cache_size
    end

    # @return [Integer] the total length of the backing object.
    attr_reader :total_size

    # @return [Object] the identity this IO was opened against.
    attr_reader :identity

    # @return [Integer] the current cursor position.
    def tell
      @pos
    end

    alias pos tell

    # Moves the cursor. Negative offsets or a resulting position before the
    # start of the object raise Zip::InvalidRangeError. Seeking to the very
    # end is allowed; a subsequent read is range-checked like any other.
    def seek(offset, whence = IO::SEEK_SET)
      new_pos =
        case whence
        when IO::SEEK_SET then offset
        when IO::SEEK_CUR then @pos + offset
        when IO::SEEK_END then @total_size + offset
        else raise ArgumentError, "invalid whence: #{whence}"
        end
      check_integer(new_pos, 'offset')
      if new_pos.negative?
        raise InvalidRangeError,
              "cannot seek before the start of the object (offset #{new_pos})"
      end

      @pos = new_pos
      0
    end

    # @return [Boolean] true when the cursor is at or past the end.
    def eof?
      @pos >= @total_size
    end

    alias eof eof?

    # A no-op so code that switches a stream to binary mode works unchanged.
    def binmode
      self
    end

    # Reads up to +length+ bytes from the current cursor position. With no
    # argument, reads everything from the cursor to the end of the object.
    # Asking to read past the end of the object raises
    # Zip::InvalidRangeError rather than returning a short buffer.
    #
    # @return [String, nil] the bytes read, or nil at end of file.
    def read(length = nil)
      ensure_open!
      check_identity!
      return nil if eof?

      if length.nil?
        length = @total_size - @pos
      else
        length = check_integer(length, 'length')
        raise InvalidRangeError, "negative length #{length}" if length.negative?
      end
      return +''.b if length.zero?

      if @pos + length > @total_size
        raise InvalidRangeError,
              "read of #{length} bytes at #{@pos} exceeds object size " \
              "#{@total_size}"
      end

      data = read_exact(@pos, length)
      @pos += length
      data
    end

    # Does not close any network connection (this IO does not own one); it
    # merely marks this cursor unusable, mirroring IO#close.
    def close
      @closed = true
      nil
    end

    def closed?
      @closed
    end

    # Returns an independent cursor over the same source and cache. This is
    # used by Zip::InputStream so reading one entry does not disturb the
    # cursor the central directory was parsed with.
    def dup
      copy = super
      copy.send(:initialize_dup, self)
      copy
    end

    private

    def initialize_dup(original)
      @source = original.instance_variable_get(:@source)
      @total_size = original.total_size
      @identity = original.identity
      @pos = 0
      @closed = original.closed?
      @cache = original.instance_variable_get(:@cache)
      @cache_order = original.instance_variable_get(:@cache_order)
      @max_cached = original.instance_variable_get(:@max_cached)
    end

    def ensure_open!
      raise IOError, 'closed stream' if @closed
    end

    def check_integer(value, name)
      return value if value.kind_of?(Integer) && !value.kind_of?(Float)

      raise ArgumentError, "#{name} must be an Integer, got #{value.class}"
    end

    def validate_range!(offset, length)
      check_integer(offset, 'offset')
      check_integer(length, 'length')
      if offset.negative? || length.negative?
        raise InvalidRangeError,
              "negative range (offset #{offset}, length #{length})"
      end
      return if length.zero?

      return unless offset > @total_size || offset + length > @total_size

      raise InvalidRangeError,
            "range #{offset}...#{offset + length} exceeds object size " \
            "#{@total_size}"
    end

    # Returns exactly +length+ bytes at +offset+, serving identical repeated
    # requests from the cache. The identity check happens in #read, so even
    # a cache hit is refused once the backing object has changed.
    def read_exact(offset, length)
      validate_range!(offset, length)

      key = [offset, length]
      cached = @cache[key]
      if cached
        @cache_order.delete(key)
        @cache_order.push(key)
        return cached.dup
      end

      data = fetch(offset, length)
      remember(key, data)
      data.dup
    end

    def fetch(offset, length)
      check_identity!
      data = @source.read_at(offset, length)
      unless data.kind_of?(String) && data.bytesize == length
        got = data.kind_of?(String) ? data.bytesize : 0
        raise ShortReadError.new(offset, length, got)
      end
      data.dup.force_encoding(Encoding::BINARY)
    end

    def check_identity!
      current = @source.identity
      return if current == @identity

      # The object changed underneath us: drop everything cached against the
      # old version and abort this read.
      @cache.clear
      @cache_order.clear
      raise ObjectChangedError.new(@identity, current)
    end

    def remember(key, data)
      @cache.delete(@cache_order.shift) if @cache_order.size >= @max_cached
      @cache[key] = data
      @cache_order.push(key)
    end
  end
end
