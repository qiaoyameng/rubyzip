# frozen_string_literal: true

module Zip
  # The superclass for all rubyzip error types. Simply rescue this one if
  # you don't need to know what sort of error has been raised.
  class Error < StandardError; end

  # Error raised if an unsupported compression method is used.
  class CompressionMethodError < Error
    # The compression method that has caused this error.
    attr_reader :compression_method

    # Create a new CompressionMethodError with the specified incorrect
    # compression method.
    def initialize(method)
      super()
      @compression_method = method
    end

    # The message returned by this error.
    def message
      "Unsupported compression method: #{COMPRESSION_METHODS[@compression_method]}."
    end
  end

  # Error raised if there is a problem while decompressing an archive entry.
  class DecompressionError < Error
    # The error from the underlying Zlib library that caused this error.
    attr_reader :zlib_error

    # Create a new DecompressionError with the specified underlying Zlib
    # error.
    def initialize(zlib_error)
      super()
      @zlib_error = zlib_error
    end

    # The message returned by this error.
    def message
      "Zlib error ('#{@zlib_error.message}') while inflating."
    end
  end

  # Error raised when trying to extract an archive entry over an
  # existing file.
  class DestinationExistsError < Error
    # Create a new DestinationExistsError with the clashing destination.
    def initialize(destination)
      super()
      @destination = destination
    end

    # The message returned by this error.
    def message
      "Cannot create file or directory '#{@destination}'. " \
        'A file already exists with that name.'
    end
  end

  # Error raised when trying to add an entry to an archive where the
  # entry name already exists.
  class EntryExistsError < Error
    # Create a new EntryExistsError with the specified source and name.
    def initialize(source, name)
      super()
      @source = source
      @name = name
    end

    # The message returned by this error.
    def message
      "'#{@source}' failed. Entry #{@name} already exists."
    end
  end

  # Error raised when an entry name is invalid.
  class EntryNameError < Error
    # Create a new EntryNameError with the specified name.
    def initialize(name = nil)
      super()
      @name = name
    end

    # The message returned by this error.
    def message
      if @name.nil?
        'Illegal entry name. Names must have fewer than 65,536 characters.'
      else
        "Illegal entry name '#{@name}'. Names must not start with '/'."
      end
    end
  end

  # Error raised if an entry is larger on extraction than it is advertised
  # to be.
  class EntrySizeError < Error
    # The entry that has caused this error.
    attr_reader :entry

    # Create a new EntrySizeError with the specified entry.
    def initialize(entry)
      super()
      @entry = entry
    end

    # The message returned by this error.
    def message
      "Entry '#{@entry.name}' should be #{@entry.size}B, but is larger when inflated."
    end
  end

  class EntryNumberMismatchError < Error
    # Create a new EntryNumberMismatchError with the specified size and size in bytes.
    def initialize(size, size_in_bytes)
      super()
      @size = size
      @size_in_bytes = size_in_bytes
    end

    # The message returned by this error.
    def message
      "Zip consistency problem: an impossibly high number of entries (#{@size}) " \
        'is declared in this file, compared to the size of the central directory ' \
        "(#{@size_in_bytes} bytes)."
    end
  end

  # Error raised if a split archive is read. Rubyzip does not support reading
  # split archives.
  class SplitArchiveError < Error
    # The message returned by this error.
    def message
      'Rubyzip cannot extract from split archives at this time.'
    end
  end

  # Error raised if there is not enough metadata for the entry to be streamed.
  class StreamingError < Error
    # The entry that has caused this error.
    attr_reader :entry

    # Create a new StreamingError with the specified entry.
    def initialize(entry)
      super()
      @entry = entry
    end

    # The message returned by this error.
    def message
      "The local header of this entry ('#{@entry.name}') does not contain " \
        'the correct metadata for `Zip::InputStream` to be able to ' \
        'uncompress it. Please use `Zip::File` instead of `Zip::InputStream`.'
    end
  end

  # Error raised when a {Zip::RangeSource} is used incorrectly: when a
  # requested range is negative, extends beyond the advertised size of the
  # object, or otherwise cannot be satisfied.
  class RangeError < Error
    # Create a new RangeError describing an invalid request for the range
    # starting at +offset+ with the given +length+, for an object of
    # +object_size+ bytes.
    def initialize(offset, length, object_size)
      super()
      @offset = offset
      @length = length
      @object_size = object_size
    end

    # The message returned by this error.
    def message
      "Invalid range (offset=#{format_part(@offset)}, " \
        "length=#{format_part(@length)}) " \
        "for object of size #{@object_size}."
    end

    private

    def format_part(value)
      value.nil? ? 'unspecified' : value
    end
  end

  # Error raised when a {Zip::RangeSource} returns fewer bytes than were
  # requested for a range that lies entirely inside the object.
  class ShortReadError < Error
    # Create a new ShortReadError for a request of +requested+ bytes at
    # +offset+ that only returned +received+ bytes.
    def initialize(offset, requested, received)
      super()
      @offset = offset
      @requested = requested
      @received = received
    end

    # The message returned by this error.
    def message
      "Short read at offset #{@offset}: expected #{@requested} bytes " \
        "but got #{@received}."
    end
  end

  # Error raised when the object backing a {Zip::RangeSource} changes
  # identity (and therefore, potentially, content) while a zip archive is
  # being read from it. Bytes from two different versions of the object must
  # never be mixed, so any cached data is discarded and the current read is
  # aborted.
  class ObjectChangedError < Error
    # Create a new ObjectChangedError, optionally including the expected and
    # actual identities.
    def initialize(expected = nil, actual = nil)
      super()
      @expected = expected
      @actual = actual
    end

    # The message returned by this error.
    def message
      if @expected.nil? && @actual.nil?
        return 'The range source object changed during reading. Any cached ' \
               'data has been discarded and the read was aborted.'
      end

      'The range source object changed during reading (expected identity ' \
        "#{@expected.inspect} but got #{@actual.inspect}). " \
        'Any cached data has been discarded and the read was aborted.'
    end
  end
end
