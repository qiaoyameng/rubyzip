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

  # Error raised when a read is requested at an invalid position in a
  # {RangeSource}: a non-integer or negative offset/length, or a range that
  # reaches past the end of the object.
  class InvalidRangeError < Error; end

  # Error raised when a {RangeSource#read_at} call returns fewer bytes than
  # were requested (despite the range being in bounds). The remote object is
  # assumed to be immutable for the lifetime of a read, so a short read
  # means the object cannot be parsed reliably.
  #
  # This inherits from StandardError rather than Error so it is not silently
  # swallowed by the content-parsing layer that rescues Zip::Error to
  # recover from corrupt entries: a transport failure must always abort the
  # current read.
  class ShortReadError < StandardError
    # The offset at which the read was attempted.
    attr_reader :offset

    # The number of bytes requested.
    attr_reader :length

    # The number of bytes actually returned.
    attr_reader :bytes_read

    # Create a new ShortReadError for a read of +length+ bytes at +offset+
    # that only returned +bytes_read+ bytes.
    def initialize(offset, length, bytes_read)
      super()
      @offset = offset
      @length = length
      @bytes_read = bytes_read
    end

    # The message returned by this error.
    def message
      "Short read from range source at offset #{@offset}: expected " \
        "#{@length} bytes but got #{@bytes_read}"
    end
  end

  # Error raised when the object backing a {RangeSource} changes (its
  # identity differs from the one the archive was opened with) while a read
  # is in progress. The current read is aborted so that bytes from two
  # different versions of the object are never mixed together. See
  # ShortReadError for why this inherits from StandardError rather than
  # Error.
  class ObjectChangedError < StandardError
    # The identity the archive was opened with.
    attr_reader :expected_identity

    # The identity observed on the most recent read.
    attr_reader :actual_identity

    # Create a new ObjectChangedError.
    def initialize(expected_identity, actual_identity)
      super()
      @expected_identity = expected_identity
      @actual_identity = actual_identity
    end

    # The message returned by this error.
    def message
      'The backing object changed while reading the zip archive ' \
        "(expected identity #{@expected_identity.inspect}, " \
        "got #{@actual_identity.inspect})"
    end
  end
end
