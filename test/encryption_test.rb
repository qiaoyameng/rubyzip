# frozen_string_literal: true

require_relative 'test_helper'
require 'securerandom'

class EncryptionTest < Minitest::Test
  DATA_DIR = 'test/data'
  ENCRYPT_ZIP_TEST_FILE = 'zipWithEncryption.zip'
  AES_128_ZIP_TEST_FILE = 'zip-aes-128.zip'
  AES_256_ZIP_TEST_FILE = 'zip-aes-256.zip'
  AES_KEKA_ZIP_TEST_FILE = 'aes-keka.zip'
  INPUT_FILE1 = 'file1.txt'
  INPUT_FILE2 = 'file2.txt'
  INPUT_FILE3 = 'zip-aes-128.txt'
  INPUT_FILE4 = 'zip-aes-256.txt'
  INPUT_FILE5 = 'mimetype'

  def setup
    Zip.default_compression = ::Zlib::DEFAULT_COMPRESSION
  end

  def teardown
    Zip.reset!
  end

  def test_encrypt
    content = File.read("#{DATA_DIR}/#{INPUT_FILE1}")
    test_filename = 'top_secret_file.txt'

    password = 'swordfish'

    encrypted_zip = Zip::OutputStream.write_buffer(
      ::StringIO.new,
      encrypter: Zip::TraditionalEncrypter.new(password)
    ) do |out|
      out.put_next_entry(test_filename)
      out.write content
    end

    Zip::InputStream.open(
      encrypted_zip, decrypter: Zip::TraditionalDecrypter.new(password)
    ) do |zis|
      entry = zis.get_next_entry
      assert_equal test_filename, entry.name
      assert_equal 1_327, entry.size
      assert_equal content, zis.read
    end
  end

  def test_decrypt
    Zip::InputStream.open(
      "#{DATA_DIR}/#{ENCRYPT_ZIP_TEST_FILE}",
      decrypter: Zip::TraditionalDecrypter.new('password')
    ) do |zis|
      entry = zis.get_next_entry
      assert_equal INPUT_FILE1, entry.name
      assert_equal 1_327, entry.size
      assert_equal ::File.read("#{DATA_DIR}/#{INPUT_FILE1}"), zis.read

      entry = zis.get_next_entry
      assert_equal INPUT_FILE2, entry.name
      assert_equal 41_234, entry.size
      assert_equal ::File.read("#{DATA_DIR}/#{INPUT_FILE2}"), zis.read
    end
  end

  def test_decrypt_with_wrong_password
    error = assert_raises(Zip::DecompressionError) do
      Zip::InputStream.open(
        "#{DATA_DIR}/#{ENCRYPT_ZIP_TEST_FILE}",
        decrypter: Zip::TraditionalDecrypter.new('wrong_password')
      ) do |zis|
        zis.get_next_entry
        zis.read
      end
    end
    assert_match(/Zlib error \('.+'\) while inflating\./, error.message)
  end

  def test_aes_128_decrypt
    Zip::InputStream.open(
      "#{DATA_DIR}/#{AES_128_ZIP_TEST_FILE}",
      decrypter: Zip::AESDecrypter.new('password', Zip::AESEncryption::STRENGTH_128_BIT)
    ) do |zis|
      entry = zis.get_next_entry
      assert_equal INPUT_FILE3, entry.name
      assert_equal 11, entry.size
      assert_equal ::File.read("#{DATA_DIR}/#{INPUT_FILE3}"), zis.read
    end
  end

  def test_aes_256_decrypt
    Zip::InputStream.open(
      "#{DATA_DIR}/#{AES_256_ZIP_TEST_FILE}",
      decrypter: Zip::AESDecrypter.new('password', Zip::AESEncryption::STRENGTH_256_BIT)
    ) do |zis|
      [INPUT_FILE3, INPUT_FILE4].each do |entry_name|
        entry = zis.get_next_entry
        assert entry
        assert_equal entry_name, entry.name
        assert entry.encrypted?
        assert_equal 11, entry.size

        file_stream = ::File.new("#{DATA_DIR}/#{INPUT_FILE3}")

        assert_equal file_stream.read(3), zis.read(3) # Ensure read with maxlen
        assert_equal file_stream.read(1), zis.read(1) # Ensure read after a read doesn't cause integrity issues
        file_stream.rewind
        zis.rewind
        assert_equal file_stream.read, zis.read # Ensure read after a rewind doesn't cause integrity issues
        file_stream.close
      end

      assert_nil zis.get_next_entry
    end
  end

  def test_aes_256_entry_decrypt
    zip_file = Zip::File.new("#{DATA_DIR}/#{AES_256_ZIP_TEST_FILE}")
    entries = zip_file.entries
    assert_equal 2, entries.size # Ensure central directory can be read when zip is encrypted

    decrypter = Zip::AESDecrypter.new('password', Zip::AESEncryption::STRENGTH_256_BIT)

    [INPUT_FILE3, INPUT_FILE4].each do |entry_name|
      entry = zip_file.find_entry(entry_name)
      assert entry
      assert entry.encrypted?

      entry.get_input_stream(decrypter: decrypter) do |entry_stream|
        input_file_stream = ::File.open("#{DATA_DIR}/#{entry_name}", 'rb')
        assert_equal input_file_stream.read(2), entry_stream.read(2)
        assert_equal input_file_stream.read, entry_stream.read
      end
    end
  end

  def test_aes_encrypt
    content = File.read("#{DATA_DIR}/#{INPUT_FILE1}")
    test_filename = 'top_secret_file.txt'
    password = 'swordfish'

    [
      Zip::AESEncryption::STRENGTH_128_BIT,
      Zip::AESEncryption::STRENGTH_256_BIT
    ].each do |strength|
      encrypted_zip = Zip::OutputStream.write_buffer(
        StringIO.new,
        encrypter: Zip::AESEncrypter.new(password, strength)
      ) do |out|
        out.put_next_entry(test_filename)
        out.write content
      end

      Zip::InputStream.open(
        encrypted_zip, decrypter: Zip::AESDecrypter.new(password, strength)
      ) do |zis|
        entry = zis.get_next_entry
        assert_equal test_filename, entry.name
        assert_equal 1_327, entry.size
        assert_equal content, zis.read
        assert entry.aes?
        assert entry.encrypted?
        assert_equal 0, entry.crc
        assert_equal Zip::Entry::DEFLATED, entry.compression_method
        assert_equal Zip::AESEncryption::VERSION_AE_2, entry.extra[:aes].vendor_version
        assert_equal strength, entry.extra[:aes].encryption_strength
      end
    end
  end

  def test_aes_encrypt_stored
    content = File.read("#{DATA_DIR}/#{INPUT_FILE1}")
    test_filename = 'top_secret_file.txt'
    password = 'swordfish'

    encrypted_zip = Zip::OutputStream.write_buffer(
      StringIO.new,
      encrypter: Zip::AESEncrypter.new(password, Zip::AESEncryption::STRENGTH_256_BIT)
    ) do |out|
      out.put_next_entry(test_filename, '', Zip::ExtraField.new, Zip::Entry::STORED)
      out.write content
    end

    refute_includes encrypted_zip.string, content[0, 64]

    Zip::InputStream.open(
      encrypted_zip, decrypter: Zip::AESDecrypter.new(password, Zip::AESEncryption::STRENGTH_256_BIT)
    ) do |zis|
      entry = zis.get_next_entry
      assert_equal content, zis.read
      assert_equal Zip::Entry::STORED, entry.compression_method
    end
  end

  def test_aes_encrypt_wrong_password
    encrypted_zip = Zip::OutputStream.write_buffer(
      StringIO.new,
      encrypter: Zip::AESEncrypter.new('swordfish', Zip::AESEncryption::STRENGTH_256_BIT)
    ) do |out|
      out.put_next_entry('secret.txt')
      out.write 'top secret content'
    end

    error = assert_raises(Zip::Error) do
      Zip::InputStream.open(
        encrypted_zip,
        decrypter: Zip::AESDecrypter.new('wrong_password', Zip::AESEncryption::STRENGTH_256_BIT)
      ) do |zis|
        zis.get_next_entry
        zis.read
      end
    end
    assert_equal 'Bad password', error.message
  end

  def test_aes_encrypt_with_directory
    password = 'swordfish'
    strength = Zip::AESEncryption::STRENGTH_256_BIT

    encrypted_zip = Zip::OutputStream.write_buffer(
      StringIO.new,
      encrypter: Zip::AESEncrypter.new(password, strength)
    ) do |out|
      out.put_next_entry('adir/')
      out.put_next_entry('adir/file.txt')
      out.write 'hello directory world'
    end

    Zip::InputStream.open(
      encrypted_zip, decrypter: Zip::AESDecrypter.new(password, strength)
    ) do |zis|
      dir_entry = zis.get_next_entry
      assert_equal 'adir/', dir_entry.name
      refute dir_entry.encrypted?
      refute dir_entry.aes?
      assert_equal 0, dir_entry.gp_flags

      file_entry = zis.get_next_entry
      assert_equal 'adir/file.txt', file_entry.name
      assert file_entry.encrypted?
      assert file_entry.aes?
      assert_equal 'hello directory world', zis.read
    end
  end

  def test_aes_encrypt_via_entry
    password = 'swordfish'
    strength = Zip::AESEncryption::STRENGTH_256_BIT
    content = 'hello via Zip::File'

    encrypted_zip = Zip::OutputStream.write_buffer(
      StringIO.new,
      encrypter: Zip::AESEncrypter.new(password, strength)
    ) do |out|
      out.put_next_entry('secret.txt')
      out.write content
    end

    zip_file = Zip::File.open_buffer(encrypted_zip)
    entry = zip_file.find_entry('secret.txt')
    assert entry.encrypted?

    entry.get_input_stream(decrypter: Zip::AESDecrypter.new(password, strength)) do |entry_stream|
      assert_equal content, entry_stream.read
    end
  end

  def test_aes_decrypt_keka
    Zip::InputStream.open(
      "#{DATA_DIR}/#{AES_KEKA_ZIP_TEST_FILE}",
      decrypter: Zip::AESDecrypter.new('swordfish', Zip::AESEncryption::STRENGTH_256_BIT)
    ) do |zis|
      entry = zis.get_next_entry
      assert_equal INPUT_FILE2, entry.name
      assert_equal 41_234, entry.size
      assert_equal ::File.read("#{DATA_DIR}/#{INPUT_FILE2}"), zis.read

      entry = zis.get_next_entry
      assert_equal INPUT_FILE5, entry.name
      assert_equal 20, entry.size
      assert_equal ::File.read("#{DATA_DIR}/#{INPUT_FILE5}"), zis.read
    end
  end

  def test_aes_encrypt_all_strengths
    content = ::File.binread("#{DATA_DIR}/#{INPUT_FILE1}")
    password = 'swordfish'

    [
      Zip::AESEncryption::STRENGTH_128_BIT,
      Zip::AESEncryption::STRENGTH_192_BIT,
      Zip::AESEncryption::STRENGTH_256_BIT
    ].each do |strength|
      encrypted_zip = Zip::OutputStream.write_buffer(
        StringIO.new,
        encrypter: Zip::AESEncrypter.new(password, strength)
      ) do |out|
        out.put_next_entry('secret.txt')
        out.write content
      end

      Zip::InputStream.open(
        encrypted_zip, decrypter: Zip::AESDecrypter.new(password, strength)
      ) do |zis|
        entry = zis.get_next_entry
        assert_equal content, zis.read
        assert_equal strength, entry.extra[:aes].encryption_strength
        assert_equal Zip::AESEncryption::VERSION_AE_2, entry.extra[:aes].vendor_version
      end
    end
  end

  def test_aes_encrypt_empty_entry
    password = 'swordfish'
    strength = Zip::AESEncryption::STRENGTH_256_BIT

    encrypted_zip = Zip::OutputStream.write_buffer(
      StringIO.new,
      encrypter: Zip::AESEncrypter.new(password, strength)
    ) do |out|
      out.put_next_entry('empty.txt')
    end

    Zip::InputStream.open(
      encrypted_zip, decrypter: Zip::AESDecrypter.new(password, strength)
    ) do |zis|
      entry = zis.get_next_entry
      assert_equal 'empty.txt', entry.name
      assert entry.aes?
      assert_equal 0, entry.size
      assert_equal 0, entry.crc
      assert_equal '', zis.read
    end
  end

  # STORED entries make the ciphertext line up exactly with the AES block
  # boundaries; writing in 7-byte slices forces partial blocks to be
  # buffered across `encrypt` calls.
  def test_aes_encrypt_block_boundary_sizes
    password = 'swordfish'
    strength = Zip::AESEncryption::STRENGTH_256_BIT

    [1, 15, 16, 17, 31, 32, 33, 255, 256, 257].each do |size|
      content = SecureRandom.random_bytes(size)
      encrypted_zip = Zip::OutputStream.write_buffer(
        StringIO.new,
        encrypter: Zip::AESEncrypter.new(password, strength)
      ) do |out|
        out.put_next_entry('data.bin', '', Zip::ExtraField.new, Zip::Entry::STORED)
        content.bytes.each_slice(7) { |slice| out.write(slice.pack('C*')) }
      end

      Zip::InputStream.open(
        encrypted_zip, decrypter: Zip::AESDecrypter.new(password, strength)
      ) do |zis|
        entry = zis.get_next_entry
        assert_equal size, entry.size
        assert_equal content, zis.read
      end
    end
  end

  # Sizes are unknown when the local header is first written, so they are
  # recorded in a ZIP64 extra field (rewritten with the final values on
  # close). The ZIP64 compressed size must include the AES salt, password
  # verifier and authentication code, and the CRC stays zero for AE-2.
  def test_aes_encrypt_zip64_local_header_metadata
    password = 'swordfish'
    strength = Zip::AESEncryption::STRENGTH_256_BIT
    content = 'zip64 and aes ' * 100

    encrypted_zip = Zip::OutputStream.write_buffer(
      StringIO.new,
      encrypter: Zip::AESEncrypter.new(password, strength)
    ) do |out|
      out.put_next_entry('data.txt')
      out.write content
    end
    data = encrypted_zip.string

    sig, _ver, gp_flags, method, _time, _date, crc, csize, usize,
      name_length, extra_length = data[0, 30].unpack('VvvvvvVVVvv')
    assert_equal 0x04034b50, sig
    assert_equal 1, gp_flags & 1 # encrypted
    assert_equal Zip::COMPRESSION_METHOD_AES, method
    assert_equal 0, crc # AE-2 entries store no CRC
    assert_equal 0xFFFFFFFF, csize
    assert_equal 0xFFFFFFFF, usize

    extras = {}
    extra = data[30 + name_length, extra_length]
    offset = 0
    while offset < extra.bytesize
      header_id, size = extra[offset, 4].unpack('vv')
      extras[header_id] = extra[(offset + 4), size]
      offset += 4 + size
    end

    aes_extra = extras[0x9901].unpack('va2Cv')
    assert_equal Zip::AESEncryption::VERSION_AE_2, aes_extra[0]
    assert_equal 'AE', aes_extra[1]
    assert_equal strength, aes_extra[2]
    assert_equal Zip::Entry::DEFLATED, aes_extra[3] # real compression method

    payload_offset = 30 + name_length + extra_length
    cdir_offset = data.index("PK\x01\x02", payload_offset)
    actual_compressed_size = cdir_offset - payload_offset
    zip64_original, zip64_compressed = extras[0x0001].unpack('Q<Q<')
    assert_equal content.bytesize, zip64_original
    assert_equal actual_compressed_size, zip64_compressed

    Zip::InputStream.open(
      StringIO.new(data), decrypter: Zip::AESDecrypter.new(password, strength)
    ) do |zis|
      entry = zis.get_next_entry
      assert entry.zip64?
      assert_equal content.bytesize, entry.size
      assert_equal content, zis.read
    end
  end

  def test_aes_tampered_authentication_code
    password = 'swordfish'
    strength = Zip::AESEncryption::STRENGTH_256_BIT

    encrypted_zip = Zip::OutputStream.write_buffer(
      StringIO.new,
      encrypter: Zip::AESEncrypter.new(password, strength)
    ) do |out|
      out.put_next_entry('secret.txt')
      out.write 'top secret content'
    end

    # Flip a bit in the last byte of the entry payload: the authentication
    # code trailer, which sits just before the central directory.
    data = encrypted_zip.string.dup
    cdir_offset = data.index("PK\x01\x02")
    data.setbyte(cdir_offset - 1, data.getbyte(cdir_offset - 1) ^ 0x01)

    error = assert_raises(Zip::Error) do
      Zip::InputStream.open(
        StringIO.new(data), decrypter: Zip::AESDecrypter.new(password, strength)
      ) do |zis|
        zis.get_next_entry
        zis.read
      end
    end
    assert_equal 'Integrity fault', error.message
    refute_includes error.message, password
  end
end
