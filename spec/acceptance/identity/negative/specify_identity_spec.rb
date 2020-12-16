# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'Identity - Negative' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { '#{target_parent}':
        ensure => directory
      }

      file { '#{target_parent}/#{target_file}':
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }

      acl { '#{target_parent}/#{target_file}':
        permissions  => [
          { identity => '#{id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  let(:verify_content_path) { "#{target_parent}/#{target_file}" }

  context 'Specify 257 Character String for Identity' do
    let(:target_file) { 'specify_257_char_ident.txt' }
    # Refers to group id
    let(:id) { 'nzxncvkjnzxjkcnvkjzxncvkjznxckjvnzxkjncvzxnvckjnzxkjcnvkjzxncvkjzxncvkjzxncvkjnzxkjcnvkzjxncvkjzxnvckjnzxkjcvnzxkncjvjkzxncvkjzxnvckjnzxjkcvnzxkjncvkjzxncvjkzxncvkjzxnkvcjnzxjkcvnkzxjncvkjzxncvkzckjvnzxkcvnjzxjkcnvzjxkncvkjzxnvkjsdnjkvnzxkjcnvkjznvkjxcbvzsp' } # rubocop:disable Layout/LineLength
    let(:file_content) { 'A bag of jerks.' }

    it 'applies manifest, raises error' do
      apply_manifest(acl_manifest, expect_failures: true) do |result|
        expect(result.stderr).to match(%r{Error: Failed to set permissions for })
      end
    end

    it 'verifies file data integrity' do
      expect(file(verify_content_path)).to be_file
      expect(file(verify_content_path).content).to match(%r{#{file_content}})
    end
  end

  context 'Specify Invalid Identity' do
    let(:target_file) { 'specify_invalid_ident.txt' }
    # Refers to user id
    let(:id) { 'user_not_here' }
    let(:file_content) { 'Car made of cats.' }

    it 'applies manifest, raises error' do
      apply_manifest(acl_manifest, expect_failures: true) do |result|
        expect(result.stderr).to match(%r{Error: Failed to set permissions for 'user_not_here'})
      end
    end

    it 'verifies file data integrity' do
      expect(file(verify_content_path)).to be_file
      expect(file(verify_content_path).content).to match(%r{#{file_content}})
    end
  end
end
