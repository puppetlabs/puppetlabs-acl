require 'spec_helper_acceptance'

describe 'Permissions - File - 8.3' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { '#{target_parent}':
        ensure => directory
      }

      file { '#{target_parent}/#{file_name}':
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

      acl { '#{target8dot3}':
        permissions => [
          { identity => '#{user_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  let(:acl_manifest_remove) do
    <<-MANIFEST
      acl { '#{target8dot3}':
        purge => 'listed_permissions',
        permissions => [
          { identity => '#{user_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  let(:acl_regex) { %r{.*\\bob:\(F\)} }
  let(:verify_acl_command) { "icacls #{target_parent}/#{file_name}" }
  let(:verify_content_path) { "#{target_parent}/#{file_name}" }

  context 'Add Permissions to 8.3 File' do
    let(:file_name) { 'file_short_name.txt' }
    let(:target8dot3) { 'c:/temp/FILE_S~2.TXT' }
    let(:file_content) { 'short file names are very short' }

    include_examples 'execute manifest'
  end

  context 'Remove Permissions from 8.3 File' do
    let(:file_name) { 'rem_file_short_name.txt' }
    let(:target8dot3) { 'c:/temp/REM_FI~2.TXT' }
    let(:file_content) { 'wax candle butler space station zebra glasses' }

    include_examples 'execute manifest', true
  end
end
