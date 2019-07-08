require 'spec_helper_acceptance'

describe 'Group - Negative' do
  user_type = '257_char_name'
  file_content = 'Organized chaos party.'

  parent_name = 'temp'
  target_name = "group_#{user_type}.txt"

  target_parent = "c:/#{parent_name}"
  target = "#{target_parent}/#{target_name}"
  group_id = 'jadsqddweruwqiouroaysfyuasudyfaisoyfqoiuwyefiaysdiyfzixycivzixyvciqywifyiasdiufyasdygfasirfwerqiuwyeriatsdtfastdfqwyitfastdfawerfytasdytfasydgtaisdytfiasydfiosayghiayhidfhygiasftawyegyfhgaysgfuyasgdyugfasuiyfguaqyfgausydgfaywgfuasgdfuaisydgfausasdfuygsadfyg' # rubocop:disable Metrics/LineLength

  expected_error = %r{Error:.*Group does not exist.}
  verify_content_command = "cat /cygdrive/c/#{parent_name}/#{target_name}"
  file_content_regex = %r{\A#{file_content}\z}

  acl_manifest = <<-MANIFEST
    file { "#{target_parent}":
      ensure => directory
    }

    file { "#{target}":
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

    acl { "#{target}":
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

  windows_agents.each do |agent|
    context "On Windows Agent Change Group to Local Group with Long Name on #{agent}" do
      it 'Attempt to Execute ACL Manifest' do
        execute_manifest_on(agent, acl_manifest, debug: true) do |result|
          expect(result.stderr).to match(%r{#{expected_error}})
        end

        step 'Verify File Data Integrity'
        on(agent, verify_content_command) do |result|
          expect(result.stdout).to match(%r{#{file_content_regex}})
        end
      end
    end
  end
end
