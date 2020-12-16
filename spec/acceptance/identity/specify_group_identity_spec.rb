# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'Identity - Group' do
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

      group { '#{group_id}':
        ensure => present,
      }

      acl { '#{target_parent}/#{target_file}':
        permissions  => [
          { identity => '#{group_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  let(:verify_acl_command) { "icacls #{target_parent}/#{target_file}" }
  let(:verify_content_path) { "#{target_parent}/#{target_file}" }
  let(:acl_regex) { %r{.*\\#{group_id}:\(F\)} }

  context 'Specify Group Identity' do
    let(:target_file) { 'specify_group_ident.txt' }
    let(:group_id) { 'bobs' }
    let(:file_content) { 'Cat barf.' }

    include_examples 'execute manifest and verify file'
  end

  context 'Specify Group with Long Name for Identity' do
    let(:target_file) { 'specify_long_group_ident.txt' }
    # 256 Characters
    let(:group_id) { 'nzxncvkjnzxjkcnvkjzxncvkjznxckjvnzxkjncvzxnvckjnzxkjcnvkjzxncvkjzxncvkjzxncvkjnzxkjcnvkzjxncvkjzxnvckjnzxkjcvnzxkncjvjkzxncvkjzxnvckjnzxjkcvnzxkjncvkjzxncvjkzxncvkjzxnkvcjnzxjkcvnkzxjncvkjzxncvkzckjvnzxkcvnjzxjkcnvzjxkncvkjzxnvkjsdnjkvnzxkjcnvkjznvkjxcbvzs' } # rubocop:disable Layout/LineLength
    let(:file_content) { 'Pretty little poodle dressed in noodles.' }

    include_examples 'execute manifest and verify file'
  end
end
