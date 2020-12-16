# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'Permissions - Directory - 8.3' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target}":
        ensure  => directory,
        require => File['#{target_parent}']
      }

      user { "#{user_id}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      acl { "#{target8dot3}":
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

  let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(F\)} }

  context 'Add Permissions to a 8.3 Directory' do
    let(:target) { 'c:/temp/dir_short_name' }
    let(:target8dot3) { 'c:/temp/DIR_SH~1' }
    let(:verify_acl_command) { "icacls #{target8dot3}" }

    include_examples 'execute manifest'
  end

  context 'Remove Permissions from a 8.3 Directory' do
    let(:target) { 'c:/temp/rem_dir_short_name' }
    let(:target8dot3) { 'c:/temp/REM_DI~1' }
    let(:verify_acl_command) { "icacls #{target8dot3}" }

    include_examples 'execute manifest', true
  end
end
