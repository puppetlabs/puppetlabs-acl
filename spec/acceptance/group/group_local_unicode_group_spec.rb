# frozen_string_literal: true

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

      group { "#{group_id}":
        ensure     => present
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

  context 'Change Group to Local Unicode Group' do
    let(:file_content) { 'Dangers driving drunk while insane.' }
    let(:raw_group_id) { 'group_\u4388\u542B\u3D3C\u7F4D\uF961\u4381\u53F4\u79C0\u3AB2\u8EDE' }
    let(:group_id) { "group_\u4388\u542B\u3D3C\u7F4D\uF961\u4381\u53F4\u79C0\u3AB2\u8EDE" } # 䎈含㴼罍率䎁叴秀㪲軞

    include_examples 'execute manifest and verify (with PowerShell)'
  end
end
