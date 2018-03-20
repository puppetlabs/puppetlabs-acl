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

  def verify_group_command(prefix, raw_group_id)
    "(Get-ACL 'c:/temp/#{prefix}.txt' | Where-Object { $_.Group -match ('.*\\\\' + [regex]::Unescape(\"#{raw_group_id}\")) } | Measure-Object).Count"
  end

  context 'Change Group to Local Unicode User' do
    prefix = SecureRandom.uuid.to_s
    file_content = 'Burning grass on a cold winter day.'
    raw_group_id = 'group2_\u03A3\u03A4\u03A5\u03A6'
    group_id =     "group2_\u03A3\u03A4\u03A5\u03A6" # ΣΤΥΦ

    windows_agents.each do |agent|
      context "on #{agent}" do
        it 'Execute ACL Manifest' do
          execute_manifest_on(agent, acl_manifest(prefix, file_content, group_id), { :debug => true }) do |result|
            assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
          end
        end

        it 'Verify that ACL Rights are Correct' do
          on(agent, powershell(verify_group_command(prefix, raw_group_id), 'EncodedCommand' => true)) do |result|
            assert_match(%r{^1$}, result.stdout, 'Expected ACL was not present!')
          end
        end
      end
    end
  end
end
