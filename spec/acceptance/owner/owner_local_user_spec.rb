require 'spec_helper_acceptance'

describe 'Owner - Local User' do
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

  let(:dosify_target) { "c:\\temp\\#{target_name}" }
  let(:verify_acl_command) { "cmd /c \"dir /q #{dosify_target}\"" }
  let(:verify_content_path) { "#{target_parent}/#{target_name}" }

  context 'Change Owner to Local User' do
    let(:file_content) { 'MoewMeowMoewBlahBalh!' }
    let(:target_name) { 'owner_local_user.txt' }
    let(:owner_id) { 'racecar' }
    let(:acl_regex) { %r{.*\\#{owner_id}} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify file', agent
    end
  end

  context 'Change Owner to Local User with Long Name' do
    let(:file_content) { 'Dogs are barking animals. Cats are meowing animals.' }
    let(:target_name) { 'owner_local_long_user_name.txt' }
    let(:owner_id) { 'long_user_name_gerry' }
    # The dir command chops the username at 16 characters.
    let(:acl_regex) { %r{.*\\long} }

    windows_agents.each do |agent|
      include_examples 'execute manifest and verify file', agent
    end
  end

  context 'Change Owner to Local Unicode User' do
    prefix = SecureRandom.uuid.to_s
    let(:file_content) { 'Blurpy Bing Dangle.' }
    let(:target_name) { "#{prefix}.txt" }
    let(:raw_owner_id) { '\u03A3\u03A4\u03A5\u03A6' }
    let(:owner_id) { "\u03A3\u03A4\u03A5\u03A6" } # ΣΤΥΦ
    let(:verify_acl_command) { "(Get-ACL '#{target_parent}/#{target_name}' | Where-Object { $_.Owner -match ('.*\\\\' + [regex]::Unescape(\"#{raw_owner_id}\")) } | Measure-Object).Count" }
    let(:acl_regex) { %r{^1$} }

    windows_agents.each do |agent|
      context "on #{agent}" do
        include_examples 'execute manifest and verify (with PowerShell)', agent
      end
    end
  end
end
