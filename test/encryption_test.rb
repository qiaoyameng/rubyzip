# frozen_string_literal: true

require_relative 'test_helper'

class EncryptionTest < Minitest::Test
  DATA_DIR = 'test/data'
  ENCRYPT_ZIP_TEST_FILE = 'zipWithEncryption.zip'
  AES_128_ZIP_TEST_FILE = 'zip-aes-128.zip'
  AES_256_ZIP_TEST_FILE = 'zip-aes-256.zip'
  AES_KEKA_ZIP_TEST_FILE = 'aes-keka.zip'
  INDEPENDENT_AES_ZIP_TEST_FILE = 'winzip-aes-independent.zip'
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
      Zip::AESEncryption::STRENGTH_192_BIT,
      Zip::AESEncryption::STRENGTH_256_BIT
    ].each do |strength|
      encrypted_zip = Zip::OutputStream.write_buffer(
        StringIO.new,
        encrypter: Zip::AESEncrypter.new(password, strength)
      ) do |out|
        out.put_next_entry(test_filename)
        out.write content
      end
      refute_includes encrypted_zip.string, [Zip::SPLIT_FILE_SIGNATURE].pack('V')

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
    refute_includes error.message, 'swordfish'
    refute_includes error.message, 'wrong_password'
  end

  def test_aes_encrypt_empty_entries
    password = 'swordfish'
    strength = Zip::AESEncryption::STRENGTH_256_BIT

    encrypted_zip = Zip::OutputStream.write_buffer(
      StringIO.new,
      encrypter: Zip::AESEncrypter.new(password, strength)
    ) do |out|
      out.put_next_entry('empty-stored', '', Zip::ExtraField.new, Zip::Entry::STORED)
      out.put_next_entry('empty-deflated')
    end

    Zip::InputStream.open(
      encrypted_zip, decrypter: Zip::AESDecrypter.new(password, strength)
    ) do |zis|
      stored_entry = zis.get_next_entry
      assert_equal 'empty-stored', stored_entry.name
      assert_equal 0, stored_entry.size
      assert_equal 18 + 10, stored_entry.compressed_size
      assert_equal '', zis.read

      deflated_entry = zis.get_next_entry
      assert_equal 'empty-deflated', deflated_entry.name
      assert_equal 0, deflated_entry.size
      assert_equal 18 + 2 + 10, deflated_entry.compressed_size
      assert_equal '', zis.read
    end
  end

  def test_aes_encrypt_empty_entry_rejects_tampered_authentication_code
    password = 'swordfish'
    strength = Zip::AESEncryption::STRENGTH_256_BIT
    encrypted_zip = Zip::OutputStream.write_buffer(
      StringIO.new,
      encrypter: Zip::AESEncrypter.new(password, strength)
    ) do |out|
      out.put_next_entry('empty', '', Zip::ExtraField.new, Zip::Entry::STORED)
    end

    local_entry = Zip::Entry.read_local_entry(StringIO.new(encrypted_zip.string))
    auth_code_offset =
      local_entry.local_header_offset +
      local_entry.calculate_local_header_size +
      local_entry.compressed_size - 10
    encrypted_zip.string.setbyte(
      auth_code_offset, encrypted_zip.string.getbyte(auth_code_offset) ^ 0xff
    )

    Zip::InputStream.open(
      encrypted_zip, decrypter: Zip::AESDecrypter.new(password, strength)
    ) do |zis|
      assert_raises(Zip::Error) { zis.get_next_entry }
    end
  end

  def test_aes_encrypt_streams_chunked_compressed_data
    password = 'swordfish'
    strength = Zip::AESEncryption::STRENGTH_256_BIT
    content = 'WinZip AES streaming boundary test.'.b * 4_096

    encrypted_zip = Zip::OutputStream.write_buffer(
      StringIO.new,
      encrypter: Zip::AESEncrypter.new(password, strength)
    ) do |out|
      out.put_next_entry('chunked.bin')
      content.bytes.each_slice(4_099) { |bytes| out.write bytes.pack('C*') }
    end

    Zip::InputStream.open(
      encrypted_zip, decrypter: Zip::AESDecrypter.new(password, strength)
    ) do |zis|
      entry = zis.get_next_entry
      assert_equal content.bytesize, entry.size
      assert_equal content, zis.read
    end
  end

  def test_aes_encrypt_keeps_zip64_metadata_and_real_compression_method
    password = 'swordfish'
    strength = Zip::AESEncryption::STRENGTH_256_BIT
    content = 'small content for a large declared entry'

    encrypted_zip = Zip::OutputStream.write_buffer(
      StringIO.new,
      encrypter: Zip::AESEncrypter.new(password, strength)
    ) do |out|
      entry = Zip::Entry.new(
        nil, 'large.bin', size: 0x1_0000_0000,
        compressed_size: 0x1_0000_0000, crc: 0x1234_5678
      )
      out.put_next_entry(entry)
      out.write content
    end

    zip_file = Zip::File.open_buffer(encrypted_zip)
    entry = zip_file.find_entry('large.bin')
    central_offset = encrypted_zip.string.index([0x02014b50].pack('V'))
    central_io = StringIO.new(encrypted_zip.string[central_offset..])
    central_entry = Zip::Entry.read_c_dir_entry(central_io)

    assert entry.zip64?
    assert entry.aes?
    assert_equal 0, entry.crc
    assert_equal content.bytesize, entry.size
    assert_equal Zip::Entry::DEFLATED, entry.compression_method
    assert_equal Zip::COMPRESSION_METHOD_AES, entry.__send__(:stored_compression_method)

    local_entry = Zip::Entry.read_local_entry(StringIO.new(encrypted_zip.string))
    assert local_entry.zip64?
    assert local_entry.aes?
    assert_equal Zip::COMPRESSION_METHOD_AES,
                 local_entry.__send__(:stored_compression_method)
    assert_equal Zip::Entry::DEFLATED, local_entry.compression_method
    assert_equal content.bytesize, local_entry.extra[:zip64].original_size
    assert_equal local_entry.compressed_size, local_entry.extra[:zip64].compressed_size
    assert_equal Zip::AESEncryption::VERSION_AE_2, local_entry.extra[:aes].vendor_version

    assert central_entry.zip64?
    assert_equal content.bytesize, central_entry.extra[:zip64].original_size
    assert_equal central_entry.compressed_size,
                 central_entry.extra[:zip64].compressed_size
    assert_equal 0, central_entry.crc
    assert_equal Zip::Entry::DEFLATED, central_entry.compression_method
  end

  def test_aes_write_failure_does_not_emit_a_central_directory
    encrypter = Class.new(Zip::AESEncrypter) do
      def encrypt(data)
        raise Zip::Error, 'simulated encryption failure' if data.include?('boom')

        super
      end
    end.new('swordfish', Zip::AESEncryption::STRENGTH_256_BIT)
    output = StringIO.new
    zos = Zip::OutputStream.new(output, stream: true, encrypter: encrypter)
    zos.put_next_entry('fails.txt', '', Zip::ExtraField.new, Zip::Entry::STORED)
    assert_raises(Zip::Error) { zos.write 'boom' }
    assert_raises(Zip::Error) { zos.close_buffer }

    assert_raises(Zip::Error) do
      Zip::OutputStream.write_buffer(StringIO.new, encrypter: encrypter) do |out|
        out.put_next_entry('also-fails.txt', '', Zip::ExtraField.new, Zip::Entry::STORED)
        out.write 'boom'
      end
    end

    refute_includes output.string, [0x06054b50].pack('V')
    refute_includes output.string, [0x02014b50].pack('V')
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

  def test_aes_decrypt_independent_fixed_samples
    expected = [
      {
        name:               'aes-128-deflated.txt',
        strength:           Zip::AESEncryption::STRENGTH_128_BIT,
        compression_method: Zip::Entry::DEFLATED,
        content:            "128-bit independent WinZip AE-2 vector\n"
      },
      {
        name:               'aes-192-deflated.txt',
        strength:           Zip::AESEncryption::STRENGTH_192_BIT,
        compression_method: Zip::Entry::DEFLATED,
        content:            "192-bit independent WinZip AE-2 vector\n"
      },
      {
        name:               'aes-256-stored.txt',
        strength:           Zip::AESEncryption::STRENGTH_256_BIT,
        compression_method: Zip::Entry::STORED,
        content:            '256-bit independent WinZip AE-2 vector!'
      }
    ]

    zip_data = File.binread("#{DATA_DIR}/#{INDEPENDENT_AES_ZIP_TEST_FILE}")
    Zip::File.open_buffer(zip_data) do |zip_file|
      expected.each do |attributes|
        name = attributes[:name]
        strength = attributes[:strength]
        compression_method = attributes[:compression_method]
        content = attributes[:content]
        entry = zip_file.find_entry(name)
        assert entry
        assert entry.aes?
        assert_equal 0, entry.crc
        assert_equal compression_method, entry.compression_method
        assert_equal strength, entry.extra[:aes].encryption_strength
        assert_equal Zip::AESEncryption::VERSION_AE_2, entry.extra[:aes].vendor_version

        decrypter = Zip::AESDecrypter.new('independent-password', strength)
        entry.get_input_stream(decrypter: decrypter) do |stream|
          assert_equal content, stream.read
        end
      end
    end
  end
end
