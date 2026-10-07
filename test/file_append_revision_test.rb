# frozen_string_literal: true

require 'fileutils'

require_relative 'test_helper'

class ZipFileAppendRevisionTest < Minitest::Test
  class InjectedCrash < StandardError; end

  TEST_ZIP = 'test/data/generated/append_revision_test.zip'
  JOURNAL = "#{TEST_ZIP}#{::Zip::RevisionJournal::SUFFIX}".freeze
  BIG_CONTENT = ('big-entry-content-' * 50_000).freeze

  def setup
    create_archive
  end

  def teardown
    ::Zip.reset!
    ::FileUtils.rm_f(TEST_ZIP)
    ::FileUtils.rm_f(JOURNAL)
  end

  def test_append_revision_appends_changed_entries_only
    zf = ::Zip::File.new(TEST_ZIP)
    before_bytes = ::File.binread(TEST_ZIP)
    big_offset = zf.find_entry('big.bin').local_header_offset

    zf.get_output_stream('small1.txt') { |os| os.write 'REPLACED one' }
    zf.remove('small2.txt')
    zf.get_output_stream('small3.txt') { |os| os.write 'brand new three' }
    receipt = zf.commit_append_revision

    # The original file is untouched: the new revision is a pure append,
    # and it did not rewrite the big unchanged entry.
    after_bytes = ::File.binread(TEST_ZIP)
    assert after_bytes.start_with?(before_bytes),
           'append-revision commit must not modify any existing bytes'
    assert after_bytes.bytesize < before_bytes.bytesize + BIG_CONTENT.bytesize,
           'the unchanged big entry must not be written again'

    # The receipt describes the new revision at the end of the file.
    assert_equal TEST_ZIP, receipt.path
    assert_equal 3, receipt.entry_count
    assert_equal after_bytes.bytesize, receipt.end_offset
    assert_operator receipt.cdir_offset, :>, before_bytes.bytesize
    assert_operator receipt.eocd_offset, :>, receipt.cdir_offset
    refute ::File.exist?(JOURNAL), 'journal must be cleaned up after a successful commit'

    ::Zip::File.open(TEST_ZIP) do |latest|
      assert_equal 'REPLACED one', latest.read('small1.txt')
      assert_nil latest.find_entry('small2.txt')
      assert_equal 'brand new three', latest.read('small3.txt')
      assert_equal BIG_CONTENT, latest.read('big.bin')
      assert_equal big_offset, latest.find_entry('big.bin').local_header_offset
    end
  end

  def test_unchanged_entries_are_not_read_or_recompressed
    zf = ::Zip::File.new(TEST_ZIP)
    big_entry = zf.find_entry('big.bin')

    # Any attempt to read or rewrite the unchanged entry's data fails the test.
    def big_entry.write_to_zip_output_stream(*)
      raise 'unchanged entry must not be rewritten'
    end

    def big_entry.get_input_stream(*)
      raise 'unchanged entry must not be read'
    end

    def big_entry.get_raw_input_stream(*)
      raise 'unchanged entry must not be read'
    end

    zf.get_output_stream('small1.txt') { |os| os.write 'changed' }
    zf.commit_append_revision

    ::Zip::File.open(TEST_ZIP) do |latest|
      assert_equal BIG_CONTENT, latest.read('big.bin')
    end
  end

  def test_delete_and_replace_only_affect_the_latest_revision
    zf = ::Zip::File.new(TEST_ZIP)
    base = zf.current_revision

    zf.remove('small2.txt')
    zf.get_output_stream('small1.txt') { |os| os.write 'REPLACED one' }
    zf.commit_append_revision

    ::Zip::File.open(TEST_ZIP) do |latest|
      assert_equal 'REPLACED one', latest.read('small1.txt')
      assert_nil latest.find_entry('small2.txt')
    end

    # The old revision is still readable through its receipt.
    ::Zip::File.open(TEST_ZIP, revision: base) do |old|
      assert_equal 'original one', old.read('small1.txt')
      assert_equal 'original two', old.read('small2.txt')
      assert_equal BIG_CONTENT, old.read('big.bin')
      assert_equal 3, old.entries.size
    end
  end

  def test_receipt_roundtrip_through_a_hash
    zf = ::Zip::File.new(TEST_ZIP)
    base = zf.current_revision

    assert_equal base, ::Zip::RevisionReceipt.from_h(base.to_h)
    string_keyed = ::Zip::RevisionReceipt.from_h(base.to_h.transform_keys(&:to_s))
    assert_equal base, string_keyed

    zf.get_output_stream('small1.txt') { |os| os.write 'REPLACED one' }
    zf.commit_append_revision

    ::Zip::File.open(TEST_ZIP, revision: string_keyed) do |old|
      assert_equal 'original one', old.read('small1.txt')
    end
  end

  def test_multiple_sequential_revisions
    zf = ::Zip::File.new(TEST_ZIP)
    receipts = [zf.current_revision]

    3.times do |i|
      zf.get_output_stream("rev#{i}.txt") { |os| os.write "revision #{i}" }
      receipts << zf.commit_append_revision
    end

    receipts.each_with_index do |receipt, i|
      ::Zip::File.open(TEST_ZIP, revision: receipt) do |revision|
        assert_equal 3 + i, revision.entries.size
        assert_equal BIG_CONTENT, revision.read('big.bin')
        (0...i).each { |j| assert_equal "revision #{j}", revision.read("rev#{j}.txt") }
        assert_nil revision.find_entry("rev#{i}.txt")
      end
    end
  end

  def test_current_revision_is_nil_for_an_uncommitted_archive
    zf = ::Zip::File.new('test/data/generated/never_committed.zip', create: true)
    assert_nil zf.current_revision
  ensure
    ::FileUtils.rm_f('test/data/generated/never_committed.zip')
  end

  def test_append_revision_rejects_new_archives_and_buffers
    new_path = 'test/data/generated/uncommitted_append.zip'
    ::FileUtils.rm_f(new_path)
    zf = ::Zip::File.new(new_path, create: true)
    zf.get_output_stream('a.txt') { |os| os.write 'a' }
    assert_raises(::Zip::Error) { zf.commit_append_revision }

    buffered = ::Zip::File.open_buffer(::File.binread(TEST_ZIP))
    buffered.get_output_stream('a.txt') { |os| os.write 'a' }
    assert_raises(::Zip::Error) { buffered.commit_append_revision }
  ensure
    ::FileUtils.rm_f(new_path)
  end

  def test_append_revision_without_changes_returns_current_receipt
    zf = ::Zip::File.new(TEST_ZIP)
    before_bytes = ::File.binread(TEST_ZIP)

    receipt = zf.commit_append_revision

    assert_equal zf.current_revision, receipt
    assert_equal before_bytes, ::File.binread(TEST_ZIP)
    refute ::File.exist?(JOURNAL)
  end

  def test_recovery_rolls_back_incomplete_revisions_at_each_stage
    [:body, :directory, :end_record].each do |crash_stage|
      create_archive
      confirmed_length = ::File.size(TEST_ZIP)
      zf = ::Zip::File.new(TEST_ZIP)
      base = zf.current_revision
      zf.get_output_stream('small1.txt') { |os| os.write 'REPLACED one' }

      hook = proc do |stage, io|
        next unless stage == crash_stage

        io.truncate(confirmed_length + 10)
        raise InjectedCrash
      end
      assert_raises(InjectedCrash) { zf.commit_append_revision(stage_hook: hook) }
      assert ::File.exist?(JOURNAL), 'the journal must survive a failed commit'

      # Even though part of the new revision (possibly the whole end
      # record, when crashing at :end_record) is on disk, there is no
      # completion marker, so recovery rolls back to the confirmed length.
      assert ::Zip::File.recover_append_revision(TEST_ZIP)
      assert_equal confirmed_length, ::File.size(TEST_ZIP)
      refute ::File.exist?(JOURNAL)

      ::Zip::File.open(TEST_ZIP) do |old|
        assert_equal 'original one', old.read('small1.txt')
        assert_equal BIG_CONTENT, old.read('big.bin')
      end
      ::Zip::File.open(TEST_ZIP, revision: base) do |old|
        assert_equal 'original one', old.read('small1.txt')
      end
    end
  end

  def test_completed_revision_survives_a_crash_after_the_completion_marker
    create_archive
    confirmed_length = ::File.size(TEST_ZIP)
    zf = ::Zip::File.new(TEST_ZIP)
    zf.get_output_stream('small1.txt') { |os| os.write 'REPLACED one' }

    hook = proc { |stage, _io| raise InjectedCrash if stage == :receipt }
    assert_raises(InjectedCrash) { zf.commit_append_revision(stage_hook: hook) }

    # The completion marker was already durable when the crash happened,
    # so recovery keeps the new revision.
    assert ::Zip::File.recover_append_revision(TEST_ZIP)
    assert_operator ::File.size(TEST_ZIP), :>, confirmed_length
    ::Zip::File.open(TEST_ZIP) do |latest|
      assert_equal 'REPLACED one', latest.read('small1.txt')
    end
  end

  def test_open_recovers_an_interrupted_revision_automatically
    create_archive
    confirmed_length = ::File.size(TEST_ZIP)
    zf = ::Zip::File.new(TEST_ZIP)
    zf.get_output_stream('small1.txt') { |os| os.write 'REPLACED one' }

    hook = proc do |stage, io|
      next unless stage == :directory

      io.truncate(confirmed_length + 10)
      raise InjectedCrash
    end
    assert_raises(InjectedCrash) { zf.commit_append_revision(stage_hook: hook) }
    assert ::File.exist?(JOURNAL)

    # Simply opening the archive rolls the interrupted revision back.
    ::Zip::File.open(TEST_ZIP) do |old|
      assert_equal 'original one', old.read('small1.txt')
    end
    assert_equal confirmed_length, ::File.size(TEST_ZIP)
    refute ::File.exist?(JOURNAL)
  end

  def test_recovery_refuses_to_touch_a_replaced_file
    create_archive
    zf = ::Zip::File.new(TEST_ZIP)
    zf.get_output_stream('small1.txt') { |os| os.write 'REPLACED one' }
    hook = proc { |stage, _io| raise InjectedCrash if stage == :body }
    assert_raises(InjectedCrash) { zf.commit_append_revision(stage_hook: hook) }

    # Move the crashed archive away and put a different file at the same
    # path: its identity no longer matches the journal.
    moved_path = "#{TEST_ZIP}.moved"
    ::FileUtils.mv(TEST_ZIP, moved_path)
    ::Zip::File.open(TEST_ZIP, create: true) do |other|
      other.get_output_stream('other.txt') { |os| os.write 'other' }
    end
    contents = ::File.binread(TEST_ZIP)

    assert_raises(::Zip::Error) { ::Zip::File.recover_append_revision(TEST_ZIP) }
    assert_equal contents, ::File.binread(TEST_ZIP), 'recovery must not touch the replaced file'
    assert ::File.exist?(JOURNAL), 'the journal is left in place on identity mismatch'
  ensure
    ::FileUtils.rm_f(moved_path)
    ::FileUtils.rm_f(JOURNAL)
  end

  def test_recovery_raises_if_the_file_is_shorter_than_confirmed
    create_archive
    confirmed_length = ::File.size(TEST_ZIP)
    zf = ::Zip::File.new(TEST_ZIP)
    zf.get_output_stream('small1.txt') { |os| os.write 'REPLACED one' }
    hook = proc { |stage, _io| raise InjectedCrash if stage == :body }
    assert_raises(InjectedCrash) { zf.commit_append_revision(stage_hook: hook) }

    ::File.truncate(TEST_ZIP, confirmed_length - 100)
    assert_raises(::Zip::Error) { ::Zip::File.recover_append_revision(TEST_ZIP) }
  ensure
    ::FileUtils.rm_f(JOURNAL)
  end

  def test_recovery_without_a_journal_is_a_noop
    refute ::Zip::File.recover_append_revision(TEST_ZIP)
  end

  def test_normal_commit_compacts_the_archive_and_invalidates_receipts
    zf = ::Zip::File.new(TEST_ZIP)
    base = zf.current_revision
    zf.get_output_stream('small1.txt') { |os| os.write 'REPLACED one' }
    zf.commit_append_revision
    appended_size = ::File.size(TEST_ZIP)

    # A normal commit still rewrites the whole archive, dropping the old
    # revisions' bytes.
    zf2 = ::Zip::File.new(TEST_ZIP)
    zf2.remove('big.bin')
    zf2.get_output_stream('small4.txt') { |os| os.write 'four' }
    zf2.commit
    assert_operator ::File.size(TEST_ZIP), :<, appended_size

    ::Zip::File.open(TEST_ZIP) do |latest|
      assert_equal 'REPLACED one', latest.read('small1.txt')
      assert_equal 'four', latest.read('small4.txt')
      assert_nil latest.find_entry('big.bin')
    end

    # The old revision's bytes are gone, so its receipt can no longer be read.
    assert_raises(::Zip::Error) { ::Zip::File.open(TEST_ZIP, revision: base) }
  end

  private

  def create_archive
    ::FileUtils.rm_f(TEST_ZIP)
    ::FileUtils.rm_f(JOURNAL)
    ::Zip::File.open(TEST_ZIP, create: true) do |zf|
      zf.get_output_stream('big.bin', compression_method: ::Zip::Entry::STORED) do |os|
        os.write BIG_CONTENT
      end
      zf.get_output_stream('small1.txt') { |os| os.write 'original one' }
      zf.get_output_stream('small2.txt') { |os| os.write 'original two' }
    end
  end
end
