# frozen_string_literal: true

require_relative 'test_helper'
require 'stringio'

# Tests for reading a zip archive from a Zip::RangeSource: an object that
# only supports bounded random reads (like a large object in remote
# storage). The in-memory source records every range it serves, so the
# tests can assert that access stays sparse (a large member's body is
# never downloaded when only a small member is requested).
class ZipRangeSourceTest < Minitest::Test
  LARGE_SIZE = 1_000_000
  STORED = Zip::Entry::STORED
  DEFLATED = Zip::Entry::DEFLATED

  def setup
    entries = [
      ['head.txt', 'head data payload', DEFLATED],
      ['big.bin', 'X' * LARGE_SIZE, STORED],
      ['target_stored.txt', 'TARGET STORED CONTENTS', STORED],
      ['target_deflate.txt', 'TARGET DEFLATE ' * 40, DEFLATED]
    ]
    @data = build_zip(entries)
    @source = Zip::RangeSource::InMemory.new(@data, identity: 'etag-1')
    @zip_file = Zip::File.open_from_range(@source)
    @big_entry = @zip_file.entries.find { |entry| entry.name == 'big.bin' }
  end

  def teardown
    @zip_file&.close
    ::Zip.reset!
  end

  def test_lists_entries_from_central_directory_only
    assert_equal(
      ['head.txt', 'big.bin', 'target_stored.txt', 'target_deflate.txt'],
      @zip_file.entries.map(&:name)
    )
    assert_equal(LARGE_SIZE, @big_entry.size)
  end

  def test_reads_a_stored_member_without_downloading_the_large_member
    baseline = @source.read_ranges.size

    content = @zip_file.read('target_stored.txt')

    assert_equal('TARGET STORED CONTENTS', content)
    assert(@source.bytes_read < @data.bytesize)
    assert_no_new_range_overlaps_large_body(baseline)
  end

  def test_reads_a_deflated_member_without_downloading_the_large_member
    expected = 'TARGET DEFLATE ' * 40
    baseline = @source.read_ranges.size
    content = @zip_file.read('target_deflate.txt')

    assert_equal(expected, content)
    assert(@source.bytes_read < @data.bytesize)
    assert_no_new_range_overlaps_large_body(baseline)
  end

  def test_the_initial_tail_read_is_bounded_to_the_eocd_window
    # Opening the archive reads the end-of-central-directory area only. That
    # tail is at most MAX_END_OF_CD_SIZE, regardless of the object's size.
    tail = @source.read_ranges.first
    assert(tail.first >= @data.bytesize - Zip::CentralDirectory::MAX_END_OF_CD_SIZE)
    assert(tail.last <= Zip::CentralDirectory::MAX_END_OF_CD_SIZE)
  end

  def test_read_is_sparse_even_for_a_deflated_member_that_overshoots
    # The inflater reads in fixed-size chunks; without bounding the
    # underlying reads to the entry's compressed size this would pull in
    # bytes from following entries. Here the target comes first and the
    # large entry follows, so any overshoot is directly observable.
    entries = [
      ['small_first.txt', 'S' * 16, DEFLATED],
      ['big_after.bin', 'Y' * LARGE_SIZE, STORED]
    ]
    data = build_zip(entries)
    source = Zip::RangeSource::InMemory.new(data)
    Zip::File.open_from_range(source) do |zip_file|
      big = zip_file.entries.find { |entry| entry.name == 'big_after.bin' }
      body_start = big.local_header_offset
      pre = source.read_ranges.size

      assert_equal('S' * 16, zip_file.read('small_first.txt'))

      new_ranges = source.read_ranges[pre..]
      overlap = new_ranges.select do |offset, length|
        offset < body_start + big.compressed_size && body_start < offset + length
      end
      assert_empty(overlap, "read crossed into the following large member: #{overlap}")
    end
  end

  def test_total_bytes_read_is_only_tail_plus_central_directory_plus_member
    @zip_file.read('target_stored.txt')

    # Tail (bounded by 65557), small central directory and one small member
    # plus its header: well under ten percent of the million-byte object.
    assert_operator(@source.bytes_read, :<, (@data.bytesize * 0.1).to_i)
  end

  def test_a_forged_eocd_in_the_comment_does_not_replace_the_real_record
    # Build a zip with a comment large enough to hide a forged, end-anchored
    # EOCD record. The forged record declares a comment length that makes it
    # appear to run exactly to the end of the file, which defeats a naive
    # backwards (rindex) scan.
    data = build_zip([['only.txt', 'real contents', DEFLATED]], comment: 'C' * 100)
    forged_position = data.bytesize - 48
    forged_eocd = [0x06054b50, 0, 0, 1, 1, 100, 0, 26].pack('VvvvvVVv')
    corrupted = data.dup
    corrupted[forged_position, forged_eocd.bytesize] = forged_eocd

    source = Zip::RangeSource::InMemory.new(corrupted)
    Zip::File.open_from_range(source) do |zip_file|
      assert_equal(['only.txt'], zip_file.entries.map(&:name))
      assert_equal('real contents', zip_file.read('only.txt'))
      assert_equal(100, zip_file.comment.bytesize)
    end
  end

  def test_forged_eocd_is_also_handled_on_the_stream_path
    data = build_zip([['only.txt', 'real contents', DEFLATED]], comment: 'C' * 100)
    forged_position = data.bytesize - 48
    forged_eocd = [0x06054b50, 0, 0, 1, 1, 100, 0, 26].pack('VvvvvVVv')
    corrupted = data.dup
    corrupted[forged_position, forged_eocd.bytesize] = forged_eocd

    cdir = Zip::CentralDirectory.new
    cdir.read_from_stream(StringIO.new(corrupted))
    assert_equal(['only.txt'], cdir.entries.map(&:name))
    assert_equal(100, cdir.comment.bytesize)
  end

  def test_reads_zip64_archives_with_exact_integer_offsets
    data = File.binread('test/data/zip64-sample.zip')
    source = Zip::RangeSource::InMemory.new(data)

    Zip::File.open_from_range(source) do |zip_file|
      assert_equal(2, zip_file.size)
      zip_file.entries.each do |entry|
        assert(entry.zip64?)
        content = entry.get_input_stream(&:read)
        assert_equal(entry.size, content.bytesize)
      end
    end
  end

  def test_reads_zip64_archive_with_a_maximum_length_comment
    data = File.binread('test/data/zip64_max_length_file_comment.zip')
    source = Zip::RangeSource::InMemory.new(data)

    Zip::File.open_from_range(source) do |zip_file|
      assert_equal(65_535, zip_file.comment.bytesize)
      assert_equal(2, zip_file.size)
    end
  end

  def test_a_short_read_raises_a_clear_error
    source = short_read_source(@data)

    error = assert_raises(Zip::ShortReadError) do
      Zip::File.open_from_range(source)
    end
    assert_kind_of(Integer, error.offset)
    assert_kind_of(Integer, error.length)
    assert(error.length > error.bytes_read)
  end

  def test_object_change_after_open_aborts_member_read
    @source.simulate_object_change!("#{@data}junk", new_identity: 'etag-2')

    assert_raises(Zip::ObjectChangedError) do
      @zip_file.read('target_stored.txt')
    end
    # The archive stays poisoned: bytes from the two versions can never mix.
    assert_raises(Zip::ObjectChangedError) do
      @zip_file.read('target_stored.txt')
    end
  end

  def test_object_change_during_open_aborts
    source = Zip::RangeSource::InMemory.new(@data, identity: 'v1')
    source.define_singleton_method(:identity) do
      @seen = (@seen || 0) + 1
      @seen == 1 ? 'v1' : 'v2'
    end

    assert_raises(Zip::ObjectChangedError) do
      Zip::File.open_from_range(source)
    end
  end

  def test_transport_errors_are_not_swallowed_as_corrupt_zip_data
    assert_operator(Zip::ObjectChangedError, :<, StandardError)
    refute_operator(Zip::ObjectChangedError, :<, Zip::Error)
    assert_operator(Zip::ShortReadError, :<, StandardError)
    refute_operator(Zip::ShortReadError, :<, Zip::Error)
  end

  def test_negative_and_out_of_bounds_ranges_raise_before_requesting
    range_io = Zip::RangeIO.new(@source)

    assert_raises(Zip::InvalidRangeError) { range_io.seek(-1) }
    assert_raises(Zip::InvalidRangeError) { range_io.seek(-1, IO::SEEK_CUR) }
    assert_raises(Zip::InvalidRangeError) { range_io.read(-5) }

    range_io.seek(@data.bytesize - 3)
    assert_raises(Zip::InvalidRangeError) { range_io.read(10) }

    # Nothing was fetched for the rejected ranges.
    assert_equal(@data.bytesize, range_io.total_size)
  end

  def test_non_integer_arguments_raise_argument_error
    range_io = Zip::RangeIO.new(@source)
    assert_raises(ArgumentError) { range_io.seek('10') }
    assert_raises(ArgumentError) { range_io.read('4') }

    bad_source = Object.new
    def bad_source.size
      '100'
    end

    def bad_source.identity
      1
    end

    def bad_source.read_at(_offset, _length)
      ''
    end
    assert_raises(ArgumentError) { Zip::RangeIO.new(bad_source) }
  end

  def test_a_bad_central_directory_offset_raises_a_clear_error
    corrupted = @data.dup
    eocd = corrupted.index([0x06054b50].pack('V'))
    corrupted[eocd + 16, 4] = [@data.bytesize - 1].pack('V')

    source = Zip::RangeSource::InMemory.new(corrupted)
    assert_raises(Zip::Error) do
      Zip::File.open_from_range(source)
    end
  end

  def test_missing_eocd_raises
    source = Zip::RangeSource::InMemory.new('not a zip file at all' * 10)

    assert_raises(Zip::Error, /end of central directory/) do
      Zip::File.open_from_range(source)
    end
  end

  def test_repeated_local_header_reads_are_served_from_the_cache
    # Read the same member twice: the local header ranges were fetched once.
    @zip_file.read('target_stored.txt')
    header_ranges_after_first = @source.read_ranges.dup
    @zip_file.read('target_stored.txt')

    # Reading again needs no new fetch of the static local header (30 bytes)
    # at the member's local header offset.
    entry = @zip_file.entries.find { |name| name.name == 'target_stored.txt' }
    assert_includes(
      header_ranges_after_first,
      [entry.local_header_offset, Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH]
    )
    refute_includes(
      @source.read_ranges - header_ranges_after_first,
      [entry.local_header_offset, Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH]
    )
  end

  def test_cursor_duplication_does_not_disturb_the_archive_position
    # get_input_stream duplicates the range IO internally; make sure reading
    # one member after another still works (each gets its own cursor).
    assert_equal('TARGET STORED CONTENTS', @zip_file.read('target_stored.txt'))
    assert_equal('TARGET DEFLATE ' * 40, @zip_file.read('target_deflate.txt'))
  end

  def test_open_from_range_without_a_block_closes_nothing_but_marks_done
    source = Zip::RangeSource::InMemory.new(@data)
    zip_file = Zip::File.open_from_range(source)
    assert_nil(zip_file.name)
    zip_file.close
    # The source itself is not closed (it does not even have #close).
    assert_equal('TARGET STORED CONTENTS',
                 Zip::File.open_from_range(source).read('target_stored.txt'))
  end

  def test_count_entries_reads_only_the_bounded_tail
    ranges_before = @source.read_ranges.size
    count = Zip::File.count_entries_from_range(@source)

    assert_equal(4, count)
    @source.read_ranges[ranges_before..].each do |offset, length|
      assert(offset >= @data.bytesize - Zip::CentralDirectory::MAX_END_OF_CD_SIZE)
      assert(length <= Zip::CentralDirectory::MAX_END_OF_CD_SIZE)
    end
  end

  def test_an_empty_object_raises_a_clear_error
    assert_raises(Zip::Error) do
      Zip::File.open_from_range(Zip::RangeSource::InMemory.new(''))
    end
  end

  def test_block_form_closes_the_range_cursor_but_not_the_source
    range_io = nil
    Zip::File.open_from_range(@source) do |zip_file|
      range_io = zip_file.instance_variable_get(:@range_io)
      assert_equal('TARGET STORED CONTENTS', zip_file.read('target_stored.txt'))
    end

    assert(range_io.closed?)
    # The source is owned by the caller and must still be usable.
    assert_equal(2, @source.read_at(0, 2).bytesize)
  end

  def test_zero_length_entries_are_read_as_empty_strings
    entries = [
      ['empty_stored', '', STORED],
      ['empty_deflated', '', DEFLATED]
    ]
    data = build_zip(entries)

    Zip::File.open_from_range(Zip::RangeSource::InMemory.new(data)) do |zip_file|
      assert_equal('', zip_file.read('empty_stored'))
      assert_equal('', zip_file.read('empty_deflated'))
    end
  end

  def test_aes_encrypted_member_is_decrypted_through_the_range_source
    data = File.binread('test/data/zip-aes-128.zip')
    expected = File.read('test/data/zip-aes-128.txt')

    Zip::File.open_from_range(Zip::RangeSource::InMemory.new(data)) do |zip_file|
      entry = zip_file.entries.first
      content = entry.get_input_stream(
        decrypter: Zip::AESDecrypter.new(
          'password', Zip::AESEncryption::STRENGTH_128_BIT
        ),
        &:read
      )
      assert_equal(expected, content)
    end
  end

  private

  def build_zip(entries, comment: nil)
    io = StringIO.new
    Zip::OutputStream.write_buffer(io) do |zos|
      entries.each do |name, payload, method|
        zos.put_next_entry(name, '', Zip::ExtraField.new, method)
        zos.write(payload)
      end
      zos.comment = comment unless comment.nil?
    end
    io.string
  end

  def short_read_source(data)
    klass = Class.new do
      def initialize(payload)
        @payload = payload
      end

      def size
        @payload.bytesize
      end

      def identity
        'short'
      end

      def read_at(offset, length)
        @payload.byteslice(offset, [length - 3, 1].max)
      end
    end
    klass.new(data)
  end

  def assert_no_new_range_overlaps_large_body(baseline)
    body_start = @big_entry.local_header_offset
    body_end = body_start + @big_entry.compressed_size
    new_ranges = @source.read_ranges[baseline..]
    overlap = new_ranges.select do |offset, length|
      offset < body_end && body_start < offset + length
    end
    assert_empty(overlap, "member read overlapped the large member's body: #{overlap}")
  end
end
