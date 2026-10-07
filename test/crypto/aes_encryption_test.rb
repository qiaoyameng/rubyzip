# frozen_string_literal: true

require_relative '../test_helper'
require 'securerandom'

class AESDecrypterTest < Minitest::Test
  def setup
    @decrypter256 = ::Zip::AESDecrypter.new('password', ::Zip::AESEncryption::STRENGTH_256_BIT)
    @decrypter128 = ::Zip::AESDecrypter.new('password', ::Zip::AESEncryption::STRENGTH_128_BIT)
  end

  def test_header_bytesize
    assert_equal 18, @decrypter256.header_bytesize
  end

  def test_gp_flags
    assert_equal 1, @decrypter256.gp_flags
  end

  def test_decrypt_aes256
    header = [125, 138, 163, 42, 19, 1, 155, 66, 203, 174, 183, 235, 197, 122, 232, 68, 252, 225].pack('C*')
    @decrypter256.reset!(header)
    assert_equal 'a', @decrypter256.decrypt([161].map(&:chr).join)
  end

  def test_decrypt_aes128
    header = [127, 254, 117, 113, 255, 209, 171, 131, 179, 106].pack('C*')
    @decrypter128.reset!(header)
    assert_equal [75, 4, 0].pack('C*'), @decrypter128.decrypt([34, 33, 106].map(&:chr).join)
  end

  def test_reset!
    header = [125, 138, 163, 42, 19, 1, 155, 66, 203, 174, 183, 235, 197, 122, 232, 68, 252, 225].pack('C*')
    @decrypter256.reset!(header)
    assert_equal 'a', @decrypter256.decrypt([161].map(&:chr).join)

    header = [118, 221, 166, 27, 165, 141, 24, 122, 227, 197, 52, 135, 222, 67, 221, 92, 231, 117].pack('C*')
    @decrypter256.reset!(header)
    assert_equal 'b', @decrypter256.decrypt([135].map(&:chr).join)
  end
end

class AESEncrypterTest < Minitest::Test
  STRENGTHS = [
    Zip::AESEncryption::STRENGTH_128_BIT,
    Zip::AESEncryption::STRENGTH_192_BIT,
    Zip::AESEncryption::STRENGTH_256_BIT
  ].freeze

  def setup
    @password = 'password'
  end

  FixedRandom = Struct.new(:salt) do
    def random_bytes(length)
      raise "expected #{salt.bytesize} bytes, got #{length}" unless length == salt.bytesize

      salt.dup
    end
  end

  # These values were generated independently with Python's cryptography
  # package and OpenSSL's PBKDF2-HMAC-SHA1 implementation.
  FIXED_VECTORS = {
    Zip::AESEncryption::STRENGTH_128_BIT => {
      salt:       ['0102030405060708'].pack('H*'),
      verifier:   ['882f'].pack('H*'),
      ciphertext: ['1bc2b4e246cc37907ec93ef359994510'].pack('H*'),
      auth_code:  ['effea3b1877ff0c88b27'].pack('H*')
    },
    Zip::AESEncryption::STRENGTH_192_BIT => {
      salt:       ['0102030405060708090a0b0c'].pack('H*'),
      verifier:   ['cf73'].pack('H*'),
      ciphertext: ['f56e05e2a109220df07528e213456f51'].pack('H*'),
      auth_code:  ['8a6c973137c1dba99ae5'].pack('H*')
    },
    Zip::AESEncryption::STRENGTH_256_BIT => {
      salt:       ['0102030405060708090a0b0c0d0e0f10'].pack('H*'),
      verifier:   ['4738'].pack('H*'),
      ciphertext: ['3e247f9c43a5f181740c88b86ca65448'].pack('H*'),
      auth_code:  ['93a201a846da5e1e03c8'].pack('H*')
    }
  }.freeze

  def test_header_bytesize
    encrypter = Zip::AESEncrypter.new(@password, Zip::AESEncryption::STRENGTH_256_BIT)
    encrypter.reset!
    assert_equal 18, encrypter.header_bytesize
    assert_equal 18, encrypter.header('ignored').bytesize
  end

  def test_gp_flags
    encrypter = Zip::AESEncrypter.new(@password, Zip::AESEncryption::STRENGTH_256_BIT)
    assert_equal 1, encrypter.gp_flags
  end

  def test_data_descriptor_and_crc_are_suppressed
    encrypter = Zip::AESEncrypter.new(@password, Zip::AESEncryption::STRENGTH_256_BIT)
    assert_equal '', encrypter.data_descriptor(12_345, 100, 100)
    assert_equal 0, encrypter.crc(12_345)
  end

  def test_reset_generates_a_fresh_salt_each_time
    encrypter = Zip::AESEncrypter.new(@password, Zip::AESEncryption::STRENGTH_256_BIT)

    encrypter.reset!
    first_header = encrypter.header('ignored')

    encrypter.reset!
    second_header = encrypter.header('ignored')

    refute_equal first_header, second_header
  end

  def test_encrypts_known_vectors_with_an_injected_random_source
    plaintext = 'AES fixed vector'

    FIXED_VECTORS.each do |strength, vector|
      encrypter = Zip::AESEncrypter.new(
        @password, strength, random: FixedRandom.new(vector[:salt])
      )
      encrypter.reset!

      assert_equal vector[:salt] + vector[:verifier], encrypter.header('ignored')
      assert_equal vector[:ciphertext] + vector[:auth_code],
                   encrypter.encrypt(plaintext) + encrypter.trailer
    end
  end

  def test_rejects_a_random_source_that_returns_too_few_bytes
    random = Object.new
    def random.random_bytes(_length)
      'x'
    end

    encrypter = Zip::AESEncrypter.new(
      @password, Zip::AESEncryption::STRENGTH_128_BIT, random: random
    )
    error = assert_raises(Zip::Error) { encrypter.reset! }

    assert_equal 'Random source returned 1 bytes, expected 8', error.message
    refute_includes error.message, @password
  end

  def test_rejects_unsupported_strengths_without_exposing_the_password
    error = assert_raises(Zip::Error) do
      Zip::AESEncrypter.new(@password, 99)
    end

    assert_equal 'Unsupported encryption AES strength 99', error.message
    refute_includes error.message, @password
  end

  # `trailer` returns whatever ciphertext was still buffered (a final,
  # not-yet-block-aligned remainder) followed by the 10-byte authentication
  # code, since that's what `OutputStream` needs to be able to just append
  # it straight onto the output (see `Zip::OutputStream#finalize_current_entry`).
  # These tests split it back into its two parts.
  def split_trailer(trailer)
    auth_length = Zip::AESEncryption::AUTHENTICATION_CODE_LENGTH
    [trailer[0...-auth_length], trailer[-auth_length..]]
  end

  def test_encrypt_decrypt_round_trip
    plaintext = 'the quick brown fox jumps over the lazy dog' * 100

    STRENGTHS.each do |strength|
      encrypter = Zip::AESEncrypter.new(@password, strength)
      encrypter.reset!
      header = encrypter.header('ignored')
      ciphertext = encrypter.encrypt(plaintext)
      leftover, auth_code = split_trailer(encrypter.trailer)

      decrypter = Zip::AESDecrypter.new(@password, strength)
      decrypter.reset!(header)
      decrypted = decrypter.decrypt(ciphertext + leftover)
      decrypter.check_integrity!(StringIO.new(auth_code))

      assert_equal plaintext, decrypted
    end
  end

  # Chunk sizes are deliberately *not* multiples of the 16-byte block size,
  # and don't evenly divide the plaintext either - matching how `Deflater`
  # calls `encrypt` with whatever, arbitrarily sized buffer zlib happens to
  # have flushed. This is the scenario that originally broke on JRuby: the
  # cipher must only ever be run over whole blocks internally, buffering any
  # trailing partial block until it's completed by the next chunk (or
  # flushed by `trailer`), regardless of how the caller chunks its writes.
  def test_encrypt_decrypt_round_trip_in_chunks
    plaintext = SecureRandom.random_bytes(100_003)

    encrypter = Zip::AESEncrypter.new(@password, Zip::AESEncryption::STRENGTH_256_BIT)
    encrypter.reset!
    header = encrypter.header('ignored')
    ciphertext = +''.b
    plaintext.each_char.each_slice(4097) { |chunk| ciphertext << encrypter.encrypt(chunk.join) }
    leftover, auth_code = split_trailer(encrypter.trailer)
    ciphertext << leftover

    decrypter = Zip::AESDecrypter.new(@password, Zip::AESEncryption::STRENGTH_256_BIT)
    decrypter.reset!(header)
    decrypted = +''.b
    ciphertext.each_char.each_slice(32_768) { |chunk| decrypted << decrypter.decrypt(chunk.join) }
    decrypter.check_integrity!(StringIO.new(auth_code))

    assert_equal plaintext, decrypted
  end

  def test_decrypt_with_wrong_password_raises
    encrypter = Zip::AESEncrypter.new(@password, Zip::AESEncryption::STRENGTH_256_BIT)
    encrypter.reset!
    header = encrypter.header('ignored')
    encrypter.encrypt('some data')

    decrypter = Zip::AESDecrypter.new('wrong_password', Zip::AESEncryption::STRENGTH_256_BIT)
    error = assert_raises(Zip::Error) { decrypter.reset!(header) }
    assert_equal 'Bad password', error.message
  end

  def test_tampered_ciphertext_fails_integrity_check
    encrypter = Zip::AESEncrypter.new(@password, Zip::AESEncryption::STRENGTH_256_BIT)
    encrypter.reset!
    header = encrypter.header('ignored')
    ciphertext = encrypter.encrypt('some secret data')
    leftover, auth_code = split_trailer(encrypter.trailer)
    ciphertext << leftover

    tampered = ciphertext.dup
    tampered[0] = (tampered.getbyte(0) ^ 0xFF).chr

    decrypter = Zip::AESDecrypter.new(@password, Zip::AESEncryption::STRENGTH_256_BIT)
    decrypter.reset!(header)
    decrypter.decrypt(tampered)
    error = assert_raises(Zip::Error) { decrypter.check_integrity!(StringIO.new(auth_code)) }
    assert_equal 'Integrity fault', error.message
  end

  def test_empty_ciphertext_still_checks_the_authentication_code
    STRENGTHS.each do |strength|
      encrypter = Zip::AESEncrypter.new(@password, strength)
      encrypter.reset!
      header = encrypter.header('ignored')
      auth_code = encrypter.trailer

      decrypter = Zip::AESDecrypter.new(@password, strength)
      decrypter.reset!(header)
      decrypter.check_integrity!(StringIO.new(auth_code))
    end
  end

  def test_empty_ciphertext_rejects_a_tampered_authentication_code
    encrypter = Zip::AESEncrypter.new(@password, Zip::AESEncryption::STRENGTH_256_BIT)
    encrypter.reset!
    header = encrypter.header('ignored')
    auth_code = encrypter.trailer
    auth_code.setbyte(-1, auth_code.getbyte(-1) ^ 0xff)

    decrypter = Zip::AESDecrypter.new(@password, Zip::AESEncryption::STRENGTH_256_BIT)
    decrypter.reset!(header)
    assert_raises(Zip::Error) do
      decrypter.check_integrity!(StringIO.new(auth_code))
    end
  end
end
