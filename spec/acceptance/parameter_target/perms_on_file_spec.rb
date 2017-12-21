require 'spec_helper_acceptance'

def apply_manifest_and_verify(file_name, file_content, agent, remove = nil)
  acl_regex = /.*\\bob:\(F\)/
  verify_acl_command = "icacls #{target_parent}/#{file_name}"
  verify_content_command = "cat /cygdrive/c/temp/#{file_name}"
  context "on #{agent}" do
    it 'Execute Manifest' do
      on(agent, puppet('apply', '--debug'), :stdin => acl_manifest(file_name, file_content)) do |result|
        assert_no_match(/Error:/, result.stderr, 'Unexpected error was detected!')
      end
    end

    it 'Verify that ACL Rights are Correct' do
      on(agent, verify_acl_command) do |result|
        assert_match(acl_regex, result.stdout, 'Expected ACL was not present!')
      end
    end

    if remove
      it 'Execute Remove Manifest' do
        on(agent, puppet('apply', '--debug'), :stdin => acl_manifest_remove(file_name)) do |result|
          assert_no_match(/Error:/, result.stderr, 'Unexpected error was detected!')
        end
      end

      it 'Verify that ACL Rights are Correct' do
        on(agent, verify_acl_command) do |result|
          assert_no_match(acl_regex, result.stdout, 'Unexpected ACL was present!')
        end
      end
    end

    it 'Verify File Data Integrity' do
      on(agent, verify_content_command) do |result|
        assert_match(file_content_regex(file_content), result.stdout, 'Expected file content is invalid!')
      end
    end
  end
end

describe 'Permissions - File' do

  def acl_manifest(file_name, file_content)
    return <<-MANIFEST
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
      
      acl { '#{target_parent}/#{file_name}':
        permissions => [
          { identity => '#{user_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  def acl_manifest_remove(file_name)
    return <<-MANIFEST
      acl { '#{target_parent}/#{file_name}':
        purge => 'listed_permissions',
        permissions => [
          { identity => '#{user_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  context 'Add Permissions to a File' do
    file_name = 'add_perm_file.txt'
    file_content = 'meowmeowmeow'

    windows_agents.each do |agent|
      apply_manifest_and_verify(file_name, file_content, agent)
    end
  end

  context 'Add Permissions to a File with a Long Name (259 chars)' do
    it 'This test requires PE-3075 to be resolved' do
      skip
      file_name = 'dqcEjJarQzeeNxWihARGLytPggNssxewZsopUFUoncTKAgsxsBqRigMlZEdNTEybqlVTjkDWTRASaQPyeeAsuUohncMlarIRphqIdqwyimqPphRTcKpojhTHoAgTUWiaEkiOqbeeEZKvNAhFQiELGLZghRwhKXVHuUPxWghKXVHuUPxWqmeYCHejdQOoGRYqaxwdIqiYyhhSCAhEWlggsGToSLmrgPmotSACKrREyohRBPaKRUmlgCGVtrP'
      file_content = 'Salsa Mama! Caliente!'

      windows_agents.each do |agent|
        apply_manifest_and_verify(file_name, file_content, agent)
      end
    end
  end

  context 'Remove Permissions from a File' do
    file_name = 'rem_perm_file.txt'
    file_content = 'I love puppet, puppet love puppet, puppet love!'

    windows_agents.each do |agent|
      apply_manifest_and_verify(file_name, file_content, agent, true)
    end
  end

  context 'Remove Permissions from a File with a Long Name (259 chars)' do
    it 'This test requires PE-3075 to be resolved' do
      skip
      file_name = 'rem_file_zeeNxWihARGLytPggNssxewZsopUFUoncTKAgsxsBqRigMlZEdNTEybqlVTjkDWTRASaQPyeeAsuUohncMlarIRphqIdqwyimqPphRTcKpojhTHoAgTUWiaEkiOqbeeEZKvNAhFQiELGLZghRwhKXVHuUPxWghKXVHuUPxWqmeYCHejdQOoGRYqaxwdIqiYyhhSCAhEWlggsGToSLmrgPmotSACKrREyohRBPaKRUmlgCGVtrP'
      file_content = 'Happy Happy Happy Happy Happy!'

      windows_agents.each do |agent|
        apply_manifest_and_verify(file_name, file_content, agent, true)
      end
    end
  end

  context 'Add Permissions to a Unicode File' do
    prefix = SecureRandom.uuid.to_s
    raw_filename = prefix + '_\u3140\u3145\u3176\u3145\u3172\u3142\u3144\u3149\u3151\u3167\u3169\u3159\u3158.txt'
    file_name     = "#{prefix}_\u3140\u3145\u3176\u3145\u3172\u3142\u3144\u3149\u3151\u3167\u3169\u3159\u3158.txt"
    file_content = 'Puppets and Muppets! Cats on the Interwebs!'
    verify_acl_command = "(Get-Acl ('#{target_parent}/' + [regex]::Unescape(\"#{raw_filename}\")) | ForEach-Object { $_.Access } | Where-Object { $_.IdentityReference -match '\\\\#{user_id}' -and $_.FileSystemRights -eq 'FullControl' } | Measure-Object).Count"

    windows_agents.each do |agent|
      it 'Execute Manifest' do
        apply_manifest_on(agent, acl_manifest(file_name, file_content), {:debug => true}) do |result|
          assert_no_match(/Error:/, result.stderr, 'Unexpected error was detected!')
        end
      end

      it 'Verify that ACL Rights are Correct' do
        on(agent, powershell(verify_acl_command, {'EncodedCommand' => true})) do |result|
          assert_match(/^1$/, result.stdout, 'Expected ACL was not present!')
        end
      end
    end
  end
end
