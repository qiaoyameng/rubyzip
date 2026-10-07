# frozen_string_literal: true

require 'fileutils'
require 'tmpdir'

require_relative 'test_helper'

class AppendCommitTest < Minitest::Test
  class SimulatedCrash < StandardError; end

  LARGE_CONTENT = Random.new(1234).bytes(2 * 1024 * 1024)
  SMALL_ONE = 'small one'
  SMALL_TWO = 'small two'

  def setup
    @dir = Dir.mktmpdir
    @zip_path = File.join(@dir, 'test.zip')
    build_archive(@zip_path)
    @initial_size = File.size(@zip_path)
  end

  def teardown
    FileUtils.remove_entry(@dir)
    ::Zip.reset!
  end

  def test_commit_append_appends_without_touching_existing_bytes
    before = File.binread(@zip_path)
    large_offset = ::Zip::File.open(@zip_path) { |z| z.find_entry('large.bin').local_header_offset }

    zf = ::Zip::File.open(@zip_path)
    zf.get_output_stream('small1.txt') { |f| f.write 'changed content' }
    receipt = zf.commit_append

    after = File.binread(@zip_path)
    assert_operator after.bytesize, :>, before.bytesize
    assert_equal before, after[0, before.bytesize], 'append commit must not rewrite existing bytes'
    assert_equal before.bytesize, receipt.base_length
    assert_equal after.bytesize, receipt.end_length

    ::Zip::File.open(@zip_path) do |z|
      assert_equal 'changed content', z.read('small1.txt')
      assert_equal SMALL_TWO, z.read('small2.txt')
      assert_equal LARGE_CONTENT, z.read('large.bin')
      assert_equal large_offset, z.find_entry('large.bin').local_header_offset
    end
  end

  def test_commit_append_does_not_read_unchanged_entries
    zf = ::Zip::File.open(@zip_path)
    # If the committer tries to read the unchanged large entry's data back
    # from the archive, this blows up - proving it is never touched.
    large = zf.find_entry('large.bin')
    large.instance_variable_set(:@zipfile, File.join(@dir, 'does-not-exist.zip'))

    zf.get_output_stream('small1.txt') { |f| f.write 'changed' }
    receipt = zf.commit_append
    assert receipt
  end

  def test_commit_append_returns_nil_when_nothing_to_commit
    zf = ::Zip::File.open(@zip_path)
    assert_nil zf.commit_append
    assert_equal @initial_size, File.size(@zip_path)
    refute File.exist?(journal_path(@zip_path))
  end

  def test_commit_append_on_brand_new_archive
    path = File.join(@dir, 'fresh.zip')
    zf = ::Zip::File.open(path, create: true)
    zf.get_output_stream('a.txt') { |f| f.write 'hello' }
    receipt = zf.commit_append

    assert_equal 0, receipt.base_length
    assert_equal 1, receipt.entry_count
    ::Zip::File.open(path) do |z|
      assert_equal 'hello', z.read('a.txt')
    end
  end

  def test_delete_and_replace_affect_only_the_latest_revision
    base_receipt = ::Zip::AppendCommit.current_receipt(@zip_path)

    zf = ::Zip::File.open(@zip_path)
    zf.remove('small2.txt')
    zf.get_output_stream('small1.txt') { |f| f.write 'replaced' }
    zf.commit_append

    ::Zip::File.open(@zip_path) do |z|
      assert_nil z.find_entry('small2.txt')
      assert_equal 'replaced', z.read('small1.txt')
    end

    # The old revision still sees the removed and pre-replacement entries.
    ::Zip::File.open_revision(@zip_path, base_receipt) do |old|
      assert_equal SMALL_TWO, old.read('small2.txt')
      assert_equal SMALL_ONE, old.read('small1.txt')
      assert_equal LARGE_CONTENT, old.read('large.bin')
    end
  end

  def test_old_revisions_remain_readable_through_receipt_chain
    first_receipt = ::Zip::AppendCommit.current_receipt(@zip_path)

    zf = ::Zip::File.open(@zip_path)
    zf.get_output_stream('small1.txt') { |f| f.write 'revision two' }
    second_receipt = zf.commit_append

    zf = ::Zip::File.open(@zip_path)
    zf.get_output_stream('small1.txt') { |f| f.write 'revision three' }
    zf.commit_append

    ::Zip::File.open_revision(@zip_path, first_receipt) do |rev|
      assert_equal SMALL_ONE, rev.read('small1.txt')
    end
    ::Zip::File.open_revision(@zip_path, second_receipt) do |rev|
      assert_equal 'revision two', rev.read('small1.txt')
    end
    ::Zip::File.open(@zip_path) do |rev|
      assert_equal 'revision three', rev.read('small1.txt')
    end
  end

  def test_receipt_round_trips_through_a_hash
    zf = ::Zip::File.open(@zip_path)
    zf.get_output_stream('small1.txt') { |f| f.write 'hashed' }
    receipt = zf.commit_append

    revived = ::Zip::AppendCommit::Receipt.from_h(receipt.to_h)
    assert_equal receipt.cdir_offset, revived.cdir_offset
    assert_equal receipt.end_length, revived.end_length
    ::Zip::File.open_revision(@zip_path, revived) do |rev|
      assert_equal 'hashed', rev.read('small1.txt')
    end
  end

  def test_open_revision_raises_when_revision_no_longer_present
    zf = ::Zip::File.open(@zip_path)
    zf.get_output_stream('small1.txt') { |f| f.write 'doomed' }
    receipt = zf.commit_append

    File.truncate(@zip_path, receipt.base_length)
    assert_raises(::Zip::Error) { ::Zip::File.open_revision(@zip_path, receipt) }
  end

  def test_recovery_after_crash_at_each_stage
    [:body, :directory, :end_record].each do |stage|
      path = File.join(@dir, "crash_#{stage}.zip")
      FileUtils.cp(@zip_path, path)
      base_length = File.size(path)

      zf = ::Zip::File.open(path)
      zf.get_output_stream('added.txt') { |f| f.write 'x' * 1000 }
      cdir = zf.instance_variable_get(:@cdir)

      hook = proc do |completed_stage, _committer|
        next unless completed_stage == stage

        # Simulate a torn write followed by a crash: corrupt the tail of
        # the file mid-revision, then die.
        File.truncate(path, base_length + 13)
        raise SimulatedCrash, "boom at #{completed_stage}"
      end

      assert_raises(SimulatedCrash) do
        ::Zip::AppendCommit.commit(path, cdir, after_stage: hook)
      end
      assert File.exist?(journal_path(path)), 'journal must survive the crash'

      assert_equal :truncated, ::Zip::AppendCommit.recover(path)
      refute File.exist?(journal_path(path))
      assert_equal base_length, File.size(path)

      # The old revision is fully intact and readable again.
      ::Zip::File.open(path) do |z|
        assert_equal SMALL_ONE, z.read('small1.txt')
        assert_equal LARGE_CONTENT, z.read('large.bin')
        assert_nil z.find_entry('added.txt')
      end
    end
  end

  def test_recovery_after_crash_following_completion_receipt
    path = File.join(@dir, 'crash_after_receipt.zip')
    FileUtils.cp(@zip_path, path)
    base_length = File.size(path)

    zf = ::Zip::File.open(path)
    zf.get_output_stream('added.txt') { |f| f.write 'payload' }
    cdir = zf.instance_variable_get(:@cdir)

    hook = proc do |stage, _committer|
      raise SimulatedCrash, 'boom after receipt' if stage == :receipt
    end

    assert_raises(SimulatedCrash) do
      ::Zip::AppendCommit.commit(path, cdir, after_stage: hook)
    end

    # The completion receipt was already durable, so recovery keeps the
    # new revision instead of truncating it away.
    assert_equal :completed, ::Zip::AppendCommit.recover(path)
    assert_operator File.size(path), :>, base_length
    ::Zip::File.open(path) do |z|
      assert_equal 'payload', z.read('added.txt')
    end
  end

  def test_recover_refuses_when_file_identity_changed
    path = File.join(@dir, 'replaced.zip')
    FileUtils.cp(@zip_path, path)

    zf = ::Zip::File.open(path)
    zf.get_output_stream('added.txt') { |f| f.write 'x' }
    cdir = zf.instance_variable_get(:@cdir)
    hook = proc { |stage, _| raise SimulatedCrash if stage == :body }
    assert_raises(SimulatedCrash) do
      ::Zip::AppendCommit.commit(path, cdir, after_stage: hook)
    end

    # Swap the archive for a different file (new inode) behind the
    # journal's back: recovery must refuse rather than truncate a file it
    # cannot identify.
    replacement = File.join(@dir, 'replacement.zip')
    FileUtils.cp(@zip_path, replacement)
    FileUtils.mv(replacement, path)
    assert_raises(::Zip::Error) { ::Zip::AppendCommit.recover(path) }
    assert File.exist?(journal_path(path)), 'journal must be left in place on refusal'
  end

  def test_recover_without_journal_is_a_no_op
    assert_nil ::Zip::AppendCommit.recover(@zip_path)
  end

  def test_failed_commit_is_rolled_back_by_next_commit_append
    zf = ::Zip::File.open(@zip_path)
    zf.get_output_stream('added.txt') { |f| f.write 'x' * 500 }
    cdir = zf.instance_variable_get(:@cdir)
    hook = proc { |stage, _| raise SimulatedCrash if stage == :directory }
    assert_raises(SimulatedCrash) do
      ::Zip::AppendCommit.commit(@zip_path, cdir, after_stage: hook)
    end

    # A subsequent append commit recovers first, then succeeds cleanly.
    zf2 = ::Zip::File.open(@zip_path)
    zf2.get_output_stream('other.txt') { |f| f.write 'y' }
    receipt = zf2.commit_append
    assert receipt
    refute File.exist?(journal_path(@zip_path))
    ::Zip::File.open(@zip_path) do |z|
      assert_equal 'y', z.read('other.txt')
      assert_nil z.find_entry('added.txt')
    end
  end

  def test_plain_commit_still_rewrites_the_whole_archive
    zf = ::Zip::File.open(@zip_path)
    zf.remove('small2.txt')
    zf.commit

    assert_operator File.size(@zip_path), :<, @initial_size
    ::Zip::File.open(@zip_path) do |z|
      assert_nil z.find_entry('small2.txt')
      assert_equal LARGE_CONTENT, z.read('large.bin')
    end
  end

  def test_current_receipt_describes_tip_revision
    receipt = ::Zip::AppendCommit.current_receipt(@zip_path)
    assert_equal @initial_size, receipt.end_length
    assert_equal 3, receipt.entry_count
    assert_equal receipt.cdir_offset + receipt.cdir_size, receipt.eocd_offset

    ::Zip::File.open_revision(@zip_path, receipt) do |z|
      assert_equal 3, z.entries.size
      assert_equal SMALL_ONE, z.read('small1.txt')
    end
  end

  private

  def build_archive(path)
    ::Zip::File.open(path, create: true) do |zf|
      zf.get_output_stream('large.bin') { |f| f.write LARGE_CONTENT }
      zf.get_output_stream('small1.txt') { |f| f.write SMALL_ONE }
      zf.get_output_stream('small2.txt') { |f| f.write SMALL_TWO }
    end
  end

  def journal_path(path)
    ::Zip::AppendCommit.journal_path(path)
  end
end
