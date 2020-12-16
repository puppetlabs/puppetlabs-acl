# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'Identity - User' do
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

      user { '#{user_id}':
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      acl { '#{target_parent}/#{target_file}':
        permissions  => [
          { identity => '#{user_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  let(:verify_acl_command) { "icacls #{target_parent}/#{target_file}" }

  let(:verify_content_path) { "#{target_parent}/#{target_file}" }

  context 'Specify User with Long Name for Identity' do
    let(:target_file) { 'specify_long_user_ident.txt' }
    let(:user_id) { 'user_very_long_name1' }
    let(:file_content) { 'Brown cow goes moo.' }
    let(:acl_regex) { %r{.*\\#{user_id}:\(F\)} }

    include_examples 'execute manifest and verify file'
  end
end
