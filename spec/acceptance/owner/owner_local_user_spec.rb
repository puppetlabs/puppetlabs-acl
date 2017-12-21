require 'spec_helper_acceptance'

def apply_manifest_and_verify(agent, file_content, owner_id, target_name, owner_regex)
  context "on #{agent}" do
    verify_content_command = "cat /cygdrive/c/temp/#{target_name}"
    dosify_target = "c:\\temp\\#{target_name}"
    verify_owner_command = "cmd /c \"dir /q #{dosify_target}\""

    it 'Execute ACL Manifest' do
      on(agent, puppet('apply', '--debug'), :stdin => acl_manifest(target_name, file_content, owner_id)) do |result|
        assert_no_match(/Error:/, result.stderr, 'Unexpected error was detected!')
      end
    end

    it 'Verify that ACL Rights are Correct' do
      on(agent, verify_owner_command) do |result|
        assert_match(owner_regex, result.stdout, 'Expected ACL was not present!')
      end
    end

    it 'Verify File Data Integrity' do
      on(agent, verify_content_command) do |result|
        assert_match(file_content_regex(file_content), result.stdout, 'File content is invalid!')
      end
    end
  end
end

describe 'Owner - Local User' do

  def acl_manifest(target_name, file_content, owner_id)
    return <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }
      
      file { "#{target_parent}/#{target_name}":
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }
      
      user { "#{owner_id}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }
      
      user { "#{user_id}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }
      
      acl { "#{target_parent}/#{target_name}":
        permissions  => [
          { identity => '#{user_id}',
            rights   => ['modify']
          },
        ],
        owner        => '#{owner_id}'
      }
    MANIFEST
  end

  context 'Change Owner to Local User' do
    file_content = 'MoewMeowMoewBlahBalh!'
    target_name = 'owner_local_user.txt'
    owner_id = 'racecar'
    owner_regex = /.*\\#{owner_id}/

    windows_agents.each do |agent|
      apply_manifest_and_verify(agent, file_content, owner_id, target_name, owner_regex)
    end
  end

  context 'Change Owner to Local User with Long Name' do
    file_content = 'Dogs are barking animals. Cats are meowing animals.'
    target_name = 'owner_local_long_user_name.txt'
    owner_id = 'long_user_name_gerry'
    #The dir command chops the username at 16 characters.
    owner_regex = /.*\\long/

    windows_agents.each do |agent|
      apply_manifest_and_verify(agent, file_content, owner_id, target_name, owner_regex)
    end
  end

  context 'Change Owner to Local Unicode User' do
    file_content = 'Blurpy Bing Dangle.'
    prefix = SecureRandom.uuid.to_s
    target_name = "#{prefix}.txt"
    raw_owner_id = '\u03A3\u03A4\u03A5\u03A6'
    owner_id =     "\u03A3\u03A4\u03A5\u03A6" # ΣΤΥΦ
    verify_owner_command = "(Get-ACL '#{target_parent}/#{target_name}' | Where-Object { $_.Owner -match ('.*\\\\' + [regex]::Unescape(\"#{raw_owner_id}\")) } | Measure-Object).Count"

    windows_agents.each do |agent|
      context "on #{agent}" do
        it 'Execute ACL Manifest' do
          apply_manifest_on(agent, acl_manifest(target_name, file_content, owner_id), {:debug => true}) do |result|
            assert_no_match(/Error:/, result.stderr, 'Unexpected error was detected!')
          end
        end

        it 'Verify that ACL Rights are Correct' do
          on(agent, powershell(verify_owner_command, {'EncodedCommand' => true})) do |result|
            assert_match(/^1$/, result.stdout, 'Expected ACL was not present!')
          end
        end
      end
    end
  end
end
