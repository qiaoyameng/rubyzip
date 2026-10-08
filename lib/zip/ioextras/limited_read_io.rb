# frozen_string_literal: true

module Zip
  module IOExtras
    # Wraps an IO and restricts reads to a fixed number of bytes starting at
    # the cursor's current position. This is used when reading a single zip
    # entry from a random-access source: it makes it impossible for a
    # decompressor to read past the end of the selected entry's compressed
    # data into the next entry (which could be huge).
    #
    # The wrapper is read-only and does not own the wrapped IO, so closing
    # it is a no-op.
    #
    # @api private
    class LimitedReadIo
      def initialize(io, limit)
        @io = io
        @remaining = limit
      end

      # Reads up to +maxlen+ bytes, clamped to the number of bytes left
      # before the limit. Returns nil once the limit is reached, which is
      # how the zip decompressors signal end of input.
      def read(maxlen = nil, outbuf = nil)
        return finish(outbuf) if @remaining <= 0

        want = maxlen.nil? ? @remaining : [maxlen, @remaining].min
        return finish(outbuf) if want.zero?

        chunk = @io.read(want)
        actual = chunk.nil? ? 0 : chunk.bytesize
        @remaining -= actual

        result = chunk
        if outbuf
          outbuf.replace(chunk || +''.b)
          result = outbuf
        end
        result
      end

      # Proxies everything else (eof? checks etc.) to the wrapped IO.
      def method_missing(method, ...)
        @io.send(method, ...)
      end

      def respond_to_missing?(method, include_private = false)
        @io.respond_to?(method, include_private) || super
      end

      private

      def finish(outbuf)
        outbuf&.replace(+'')
        nil
      end
    end
  end
end
