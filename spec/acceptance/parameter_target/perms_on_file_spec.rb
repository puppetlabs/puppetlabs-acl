require 'spec_helper_acceptance'

describe 'Permissions - File' do
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

      acl { '#{target_parent}/#{file_name}':
        permissions => [
          { identity => '#{user_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  let(:acl_manifest_remove) do
    <<-MANIFEST
      acl { '#{target_parent}/#{file_name}':
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

  context 'Add Permissions to a File' do
    let(:file_name) { 'add_perm_file.txt' }
    let(:file_content) { 'meowmeowmeow' }

    include_examples 'execute manifest', false, true
  end

  context 'Add Permissions to a File with a Long Name (259 chars)' do
    skip 'This test requires PE-3075 to be resolved' do
      let(:file_name) { 'dqcEjJarQzeeNxWihARGLytPggNssxewZsopUFUoncTKAgsxsBqRigMlZEdNTEybqlVTjkDWTRASaQPyeeAsuUohncMlarIRphqIdqwyimqPphRTcKpojhTHoAgTUWiaEkiOqbeeEZKvNAhFQiELGLZghRwhKXVHuUPxWghKXVHuUPxWqmeYCHejdQOoGRYqaxwdIqiYyhhSCAhEWlggsGToSLmrgPmotSACKrREyohRBPaKRUmlgCGVtrP' } # rubocop:disable Metrics/LineLength }
      let(:file_content) { 'Salsa Mama! Caliente!' }

      include_examples 'execute manifest', false, true
    end
  end

  context 'Remove Permissions from a File' do
    let(:file_name) { 'rem_perm_file.txt' }
    let(:file_content) { 'I love puppet, puppet love puppet, puppet love!' }

    include_examples 'execute manifest', true, true
  end

  context 'Remove Permissions from a File with a Long Name (259 chars)' do
    skip 'This test requires PE-3075 to be resolved' do
      let(:file_name) { 'rem_file_zeeNxWihARGLytPggNssxewZsopUFUoncTKAgsxsBqRigMlZEdNTEybqlVTjkDWTRASaQPyeeAsuUohncMlarIRphqIdqwyimqPphRTcKpojhTHoAgTUWiaEkiOqbeeEZKvNAhFQiELGLZghRwhKXVHuUPxWghKXVHuUPxWqmeYCHejdQOoGRYqaxwdIqiYyhhSCAhEWlggsGToSLmrgPmotSACKrREyohRBPaKRUmlgCGVtrP' } # rubocop:disable Metrics/LineLength
      let(:file_content) { 'Happy Happy Happy Happy Happy!' }

      include_examples 'execute manifest', true, true
    end
  end

  context 'Add Permissions to a Unicode File' do
    prefix = SecureRandom.uuid.to_s
    let(:raw_filename) { prefix + '_\u3140\u3145\u3176\u3145\u3172\u3142\u3144\u3149\u3151\u3167\u3169\u3159\u3158.txt' }
    let(:file_name) { "#{prefix}_\u3140\u3145\u3176\u3145\u3172\u3142\u3144\u3149\u3151\u3167\u3169\u3159\u3158.txt" }
    let(:file_content) { 'Puppets and Muppets! Cats on the Interwebs!' }
    let(:verify_acl_command) { "(Get-Acl ('#{target_parent}/' + [regex]::Unescape(\"#{raw_filename}\")) | ForEach-Object { $_.Access } | Where-Object { $_.IdentityReference -match '\\\\#{user_id}' -and $_.FileSystemRights -eq 'FullControl' } | Measure-Object).Count" } # rubocop:disable Metrics/LineLength
    let(:acl_regex) { %r{^1$} }

    include_examples 'execute manifest and verify (with PowerShell)'
  end
end
