require 'spec_helper_acceptance'

describe 'Group - Unicode' do
  def acl_manifest(prefix, file_content, group_id)
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

  def verify_group_command(prefix, raw_group_id)
    "(Get-ACL 'c:/temp/#{prefix}.txt' | Where-Object { $_.Group -match ('.*\\\\' + [regex]::Unescape(\"#{raw_group_id}\")) } | Measure-Object).Count"
  end

  def verify_content_command(user_type)
    "cat /cygdrive/c/group_#{user_type}.txt"
  end

  context 'Change Group to Local Unicode Group' do
    prefix = SecureRandom.uuid.to_s
    file_content = 'Dangers driving drunk while insane.'
    raw_group_id = 'group_\u4388\u542B\u3D3C\u7F4D\uF961\u4381\u53F4\u79C0\u3AB2\u8EDE'
    group_id = "group_\u4388\u542B\u3D3C\u7F4D\uF961\u4381\u53F4\u79C0\u3AB2\u8EDE" # 䎈含㴼罍率䎁叴秀㪲軞

    windows_agents.each do |agent|
      context "on #{agent}" do
        it 'Execute ACL Manifest' do
          execute_manifest_on(agent, acl_manifest(prefix, file_content, group_id), debug: true) do |result|
            expect(result.stderr).not_to match(%r{Error:})
          end
        end

        it 'Verify that ACL Rights are Correct' do
          on(agent, powershell(verify_group_command(prefix, raw_group_id), 'EncodedCommand' => true)) do |result|
            expect(result.stdout).to match(%r{^1$})
          end
        end
      end
    end
  end
end
