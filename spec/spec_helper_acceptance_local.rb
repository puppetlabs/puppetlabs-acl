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
