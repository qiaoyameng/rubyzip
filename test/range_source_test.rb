# frozen_string_literal: true

require_relative 'test_helper'
require 'stringio'

# An in-memory RangeSource that records every byte range it serves and can
# optionally simulate identity changes and short reads.
class RecordingRangeSource
  attr_reader :size, :ranges
  attr_accessor :identity

  def initialize(data, identity = 'etag-v1')
    @data = data.b
    @size = @data.bytesize
    @identity = identity
    @ranges = []
    @short = false
  end

  def read_at(offset, length)
    @ranges << [offset, length]
    result = @data.byteslice(offset, length)
    result = result.byteslice(0, result.bytesize - 1) if @short && length > 1
    result
  end

  # Replaces the underlying object, as if a new version had been uploaded.
  def replace(data, identity = 'etag-v2')
    @data = data.b
    @size = @data.bytesize
    @identity = identity
    @ranges.clear
  end

  def short!
    @short = true
  end

  # Byte intervals ever touched by read_at.
  def touched_intervals
    @ranges.map { |offset, length| (offset...(offset + length)) }
  end

  def touches?(interval)
    touched_intervals.any? { |touched| touched.first < interval.end && interval.first < touched.end }
  end
end

# A RangeSource that returns slightly too few bytes for every request.
class ShortRangeSource
  attr_reader :size, :identity

  def initialize(data)
    @data = data.b
    @size = @data.bytesize
    @identity = 'x'
  end

  def read_at(offset, length)
    @data.byteslice(offset, length).byteslice(0, length - 1)
  end
end

class ZipRangeSourceTest < Minitest::Test
  BIG_SIZE = 5_000_000

  def build_zip(comment: '', stored: true, big_size: BIG_SIZE)
    io = ::StringIO.new(+'')
    ::Zip::OutputStream.write_buffer(io) do |zos|
      if stored
        big = ::Zip::Entry.new(
          'big.zip', 'big.bin',
          compression_method: ::Zip::Entry::STORED
        )
        zos.put_next_entry(big)
      else
        zos.put_next_entry('big.bin')
      end
      zos.write('B' * big_size)
      zos.put_next_entry('small.txt')
      zos.write('hello world')
      zos.comment = comment
    end
    io.string
  end

  def source_for(data, identity = 'etag-v1')
    RecordingRangeSource.new(data, identity)
  end

  def test_protocol_requires_methods
    err = assert_raises(ArgumentError) do
      ::Zip::RangeSource::Session.new(Object.new)
    end
    assert_match(/size/, err.message)
  end

  def test_lists_entries_and_comment_without_members
    data = build_zip(comment: 'an archive comment')
    src = source_for(data)
    zf = ::Zip::File.open_range(src)
    assert_equal(%w[big.bin small.txt], zf.entries.map(&:name))
    assert_equal('an archive comment', zf.comment)
    assert_equal(2, zf.size)
    # Listing the directory must not fetch any entry body.
    assert_empty(src.ranges.select { |_, length| length > 65_557 })
  ensure
    zf&.close
  end

  def test_read_small_stored_entry_matches_content
    data = build_zip
    src = source_for(data)
    ::Zip::File.open_range(src) do |zf|
      assert_equal('hello world', zf.read('small.txt'))
    end
  end

  def test_read_small_deflated_entry_matches_content
    data = build_zip(stored: false)
    src = source_for(data)
    ::Zip::File.open_range(src) do |zf|
      assert_equal('hello world', zf.read('small.txt'))
    end
  end

  def test_get_input_stream_with_block
    data = build_zip
    src = source_for(data)
    ::Zip::File.open_range(src) do |zf|
      zf.get_input_stream('small.txt') do |is|
        assert_equal('hello', is.read(5))
        assert_equal(' world', is.read)
      end
    end
  end

  def test_reading_small_entry_does_not_fetch_big_entry_body
    data = build_zip
    big_body_start = 57 # local header of big.bin is 30 static + 7 name + 20 extra
    big_body_end = big_body_start + BIG_SIZE

    src = source_for(data)
    ::Zip::File.open_range(src) do |zf|
      zf.read('small.txt')
    end

    bulk = (big_body_start...(big_body_end - 65_557))
    refute(src.touches?(bulk),
           "fetched the big member's body: #{src.ranges.inspect}")

    total_fetched = src.ranges.sum { |_, length| length }
    assert(total_fetched < 70_000,
           "fetched #{total_fetched} bytes to read a tiny entry")
  end

  def test_can_read_big_entry_when_requested
    data = build_zip
    src = source_for(data)
    ::Zip::File.open_range(src) do |zf|
      content = zf.read('big.bin')
      assert_equal(BIG_SIZE, content.bytesize)
      assert_equal('B' * BIG_SIZE, content)
    end
  end

  def test_find_entry_and_missing_entry
    data = build_zip
    ::Zip::File.open_range(source_for(data)) do |zf|
      assert(zf.find_entry('small.txt'))
      assert_nil(zf.find_entry('nope.txt'))
      assert_raises(Errno::ENOENT) { zf.get_entry('nope.txt') }
    end
  end

  def test_forged_eocd_signature_in_comment_is_ignored
    forged = "PK#{[0x06054b50].pack('V')}payload"
    data = build_zip(comment: forged)
    src = source_for(data)
    ::Zip::File.open_range(src) do |zf|
      assert_equal(%w[big.bin small.txt], zf.entries.map(&:name))
      assert_equal(forged, zf.comment)
      assert_equal('hello world', zf.read('small.txt'))
    end
  end

  def test_ranges_are_validated_before_request
    data = build_zip
    session = ::Zip::RangeSource::Session.new(source_for(data))
    [[-1, 10], [0, -5]].each do |offset, length|
      assert_raises(::Zip::RangeError) { session.read_exact(offset, length) }
    end
    [[data.size, 1], [data.size - 5, 10]].each do |offset, length|
      assert_raises(::Zip::RangeError) { session.read_exact(offset, length) }
    end
    # A zero-length read at the very end is valid and fetches nothing.
    assert_equal('', session.read_exact(data.size, 0))
  end

  def test_non_integer_ranges_are_argument_errors
    data = build_zip
    session = ::Zip::RangeSource::Session.new(source_for(data))
    assert_raises(ArgumentError) { session.read_exact('0', 1) }
    assert_raises(ArgumentError) { session.read_exact(0, '1') }
  end

  def test_short_read_raises
    data = build_zip
    src = ShortRangeSource.new(data)
    err = assert_raises(::Zip::ShortReadError) do
      ::Zip::File.open_range(src, &:entries)
    end
    assert_kind_of(::Zip::Error, err)
  end

  def test_identity_change_before_member_read_aborts
    data = build_zip
    src = source_for(data)
    zf = ::Zip::File.open_range(src)
    src.identity = 'etag-v2'
    err = assert_raises(::Zip::ObjectChangedError) { zf.read('small.txt') }
    assert_kind_of(::Zip::Error, err)
    assert_match('etag-v1', err.message)
    assert_match('etag-v2', err.message)
  ensure
    zf&.close
  end

  def test_identity_change_discards_cache_and_aborts
    data = build_zip
    src = source_for(data)
    zf = ::Zip::File.open_range(src)
    # Prime the cache with the (still valid) tail/central directory bytes.
    assert_equal(2, zf.size)
    # Object is replaced underneath us.
    src.replace(data)
    assert_raises(::Zip::ObjectChangedError) { zf.read('small.txt') }
  ensure
    zf&.close
  end

  def test_no_bytes_mixed_across_versions
    data = build_zip
    changed = build_zip(comment: 'different version content')
    src = source_for(data)
    zf = ::Zip::File.open_range(src)
    src.replace(changed)
    assert_raises(::Zip::ObjectChangedError) { zf.read('small.txt') }
    # A fresh reader bound to the new version reads the new content.
    ::Zip::File.open_range(src) do |fresh|
      assert_equal('different version content', fresh.comment)
      assert_equal('hello world', fresh.read('small.txt'))
    end
  ensure
    zf&.close
  end

  def test_cache_is_bounded
    data = build_zip
    session = ::Zip::RangeSource::Session.new(source_for(data))
    60.times { |i| session.read_exact(i, 1) }
    cache = session.instance_variable_get(:@cache)
    assert_equal(
      ::Zip::RangeSource::Session::MAX_CACHE_ENTRIES, cache.size
    )
  end

  def test_read_real_zip64_fixture
    src = RecordingRangeSource.new(File.binread('test/data/zip64-sample.zip'))
    reference = {}
    ::Zip::File.open('test/data/zip64-sample.zip') do |zf|
      zf.each { |entry| reference[entry.name] = zf.read(entry.name) unless entry.directory? }
    end
    ::Zip::File.open_range(src) do |zf|
      reference.each do |name, expected|
        assert_equal(expected, zf.read(name), name)
      end
    end
  end

  def test_read_max_length_comment_fixture
    path = 'test/data/max_length_file_comment.zip'
    src = RecordingRangeSource.new(File.binread(path))
    ::Zip::File.open_range(src) do |zf|
      expected = ::Zip::File.open(path, &:comment)
      assert_equal(expected, zf.comment)
      assert_equal(
        ::Zip::File.open(path) { |z| z.read(z.entries.first.name) },
        zf.read(zf.entries.first.name)
      )
    end
  end

  def test_read_encrypted_entry_with_decrypter
    path = 'test/data/zipWithEncryption.zip'
    src = RecordingRangeSource.new(File.binread(path))
    expected = ::Zip::File.open(path) do |z|
      z.get_input_stream(
        z.entries.first, decrypter: ::Zip::TraditionalDecrypter.new('password')
      ).read
    end
    ::Zip::File.open_range(src) do |zf|
      actual = zf.get_input_stream(
        zf.entries.first, decrypter: ::Zip::TraditionalDecrypter.new('password')
      ).read
      assert_equal(expected, actual)
    end
  end

  def test_read_aes_encrypted_entry_with_decrypter
    path = 'test/data/zip-aes-128.zip'
    src = RecordingRangeSource.new(File.binread(path))
    expected = ::Zip::File.open(path) do |z|
      z.get_input_stream(
        z.entries.first, decrypter: ::Zip::AESDecrypter.new('password', ::Zip::AESEncryption::STRENGTH_128_BIT)
      ).read
    end
    ::Zip::File.open_range(src) do |zf|
      actual = zf.get_input_stream(
        zf.entries.first, decrypter: ::Zip::AESDecrypter.new('password', ::Zip::AESEncryption::STRENGTH_128_BIT)
      ).read
      assert_equal(expected, actual)
    end
  end

  def test_empty_object_is_an_error
    src = RecordingRangeSource.new('')
    assert_raises(::Zip::Error) do
      ::Zip::File.open_range(src, &:entries)
    end
  end

  def test_bad_central_directory_offset_is_an_error
    data = build_zip
    eocd_position = data.bytesize - 22
    corrupted = data.dup
    corrupted[eocd_position + 16, 4] = [0x7fff_ffff].pack('V') # cdir offset
    corrupted[eocd_position + 12, 4] = [0x7fff_ffff].pack('V') # cdir size
    src = RecordingRangeSource.new(corrupted)
    err = assert_raises(::Zip::Error) do
      ::Zip::File.open_range(src, &:entries)
    end
    assert_match(/central directory/i, err.message)
  end

  def test_ranged_archive_is_read_only
    data = build_zip
    src = source_for(data)
    zf = ::Zip::File.open_range(src)
    assert_nil(zf.commit)
    assert_nil(zf.close)
    # Closing/committing never writes back through the source.
    ::Zip::File.open_range(src) do |reopened|
      assert_equal('hello world', reopened.read('small.txt'))
    end
  end
end
