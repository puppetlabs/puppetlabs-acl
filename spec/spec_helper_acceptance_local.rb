# frozen_string_literal: true

Dir['./spec/support/**/*.rb'].sort.each { |f| require f }

def target_parent
  'c:/temp'
end

def user_id
  'bob'
end

def generate_random_username
  charset = Array('A'..'Z') + Array('a'..'z')
  Array.new(5) { charset.sample }.join
end

def file_content_regex(file_content)
  %r{\A#{file_content}\z}
end

def windows_agents
  agents.select { |agent| agent['platform'].include?('windows') }
end

def linux_agents
  agents.select { |agent| fact_on(agent, 'kernel') == 'Linux' }
end

def acl_idempotent_apply(manifest)
  apply_manifest(manifest, catch_failures: true)
  apply_manifest(manifest, catch_changes: true)
end

# The following are modified helpers from beaker-4.7.0/lib/beaker/dsl/wrappers.rb

# Returns a {Beaker::Command} object for executing powershell commands on a host
#
# @param [String]   command   The powershell command to execute
# @param [Hash]     args      The commandline parameters to be passed to powershell
#
# @example Setting the contents of a file
#     powershell("Set-Content -path 'fu.txt' -value 'fu'")
#
# @example Using an alternative execution policy
#     powershell("Set-Content -path 'fu.txt' -value 'fu'", {'ExecutionPolicy' => 'Unrestricted'})
#
# @example Using an EncodedCommand (defaults to non-encoded)
#     powershell("Set Content -path 'fu.txt', -value 'fu'", {'EncodedCommand => true})
#
# @example executing from a file
#     powershell("", {'-File' => '/path/to/file'})
#
# @return [Command]
def powershell(command, args = {})
  ps_opts = {
    'ExecutionPolicy' => 'Bypass',
    'InputFormat' => 'None',
    'NoLogo' => '',
    'NoProfile' => '',
    'NonInteractive' => ''
  }
  encoded = false
  ps_opts.merge!(args)
  ps_args = []

  # determine if the command should be encoded
  if ps_opts.key?('EncodedCommand')
    v = ps_opts.delete('EncodedCommand')
    # encode the commend if v is true, nil or empty
    encoded = v || v.eql?('') || v.nil?
  end

  ps_opts.each do |key, value|
    ps_args << if value.eql?('') || value.nil?
                 "-#{key}"
               else
                 "-#{key} #{value}"
               end
  end

  # may not have a command if executing a file
  if command && !command.empty?
    ps_args << if encoded
                 "-EncodedCommand #{encode_command(command)}"
               else
                 "-Command #{command}"
               end
  end

  "powershell.exe #{ps_args.join(' ')}"
end

# Convert the provided command string to Base64
# @param [String] cmd The command to convert to Base64
# @return [String] The converted string
# @api private
def encode_command(cmd)
  cmd = cmd.chars.to_a.join("\x00").chomp
  cmd << "\x00" unless cmd[-1].eql? "\x00"
  # use strict_encode because linefeeds are not correctly handled in our model
  Base64.strict_encode64(cmd).chomp
end
