require 'spec_helper_acceptance'

prefix = SecureRandom.uuid.to_s

describe 'Group - Unicode' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "c:/temp/#{prefix}.txt":
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }

      user { "#{user_id}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      user { "#{group_id}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      acl { "c:/temp/#{prefix}.txt":
        purge           => 'true',
        permissions     => [
          { identity    => 'CREATOR GROUP',
            rights      => ['modify']
          },
          { identity    => '#{user_id}',
            rights      => ['read']
          },
          { identity    => 'Administrators',
            rights      => ['full'],
            affects     => 'all',
            child_types => 'all'
          }
        ],
        group           => '#{group_id}',
        inherit_parent_permissions => 'false'
      }
    MANIFEST
  end

  let(:verify_acl_command) { "(Get-ACL 'c:/temp/#{prefix}.txt' | Where-Object { $_.Group -match ('.*\\\\' + [regex]::Unescape(\"#{raw_group_id}\")) } | Measure-Object).Count" }
  let(:acl_regex) { %r{^1$} }

  context 'Change Group to Local Unicode User' do
    let(:file_content) { 'Burning grass on a cold winter day.' }
    let(:raw_group_id) { 'group2_\u03A3\u03A4\u03A5\u03A6' }
    let(:group_id) {     "group2_\u03A3\u03A4\u03A5\u03A6" } # ΣΤΥΦ

    windows_agents.each do |agent|
      context "on #{agent}" do
        include_examples 'execute manifest and verify (with PowerShell)', agent
      end
    end
  end
end
