require 'spec_helper_acceptance'

describe 'Owner - Local Group' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target_parent}/#{target_name}":
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }

      group { "#{owner_id}":
        ensure     => present
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

  let(:dosify_target) { "c:\\temp\\#{target_name}" }
  let(:verify_acl_command) { "cmd /c \"dir /q #{dosify_target}\"" }
  let(:verify_content_path) { "#{target_parent}/#{target_name}" }

  context 'Change Owner to Local Group' do
    let(:file_content) { 'Spearhead was a great MOHAA game.' }
    let(:target_name) { 'owner_local_group.txt' }
    let(:owner_id) { 'jerks' }
    let(:acl_regex) { %r{.*\\jerks} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify file', agent
    end
  end

  context 'Change Owner to Local Group with Long Name' do
    let(:file_content) { 'Cow are animals with mooing capabilities.' }
    let(:target_name) { 'owner_local_long_group_name.txt' }
    let(:owner_id) { 'jasqddweruwqiouroaysfyuasudyfaisoyfqoiuwyefiaysdiyfzixycivzixyvciqywifyiasdiufyasdygfasirfwerqiuwyeriatsdtfastdfqwyitfastdfawerfytasdytfasydgtaisdytfiasydfiosayghiayhidfhygiasftawyegyfhgaysgfuyasgdyugfasuiyfguaqyfgausydgfaywgfuasgdfuaisydgfausasdfuygsadfyg' } # rubocop:disable Metrics/LineLength
    let(:acl_regex) { %r{.*\\jasq} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify file', agent
    end
  end

  context 'Change Owner to Local Unicode Group' do
    prefix = SecureRandom.uuid.to_s
    let(:file_content) { 'I thought things on a Saturday night.' }
    let(:target_name) { "#{prefix}.txt" }
    let(:raw_owner_id) { '\u4388\u542B\u3D3C\u7F4D\uF961\u4381\u53F4\u79C0\u3AB2\u8EDE' }
    let(:owner_id) { "\u4388\u542B\u3D3C\u7F4D\uF961\u4381\u53F4\u79C0\u3AB2\u8EDE" } # 䎈含㴼罍率䎁叴秀㪲軞
    let(:verify_acl_command) { "(Get-ACL '#{target_parent}/#{target_name}' | Where-Object { $_.Owner -match ('.*\\\\' + [regex]::Unescape(\"#{raw_owner_id}\")) } | Measure-Object).Count" }
    let(:acl_regex) { %r{^1$} }

    windows_agents.each do |agent|
      context "on #{agent}" do
        include_examples 'execute manifest and verify (with PowerShell)', agent
      end
    end
  end
end
