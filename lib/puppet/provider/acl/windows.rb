require 'puppet/type'

Puppet::Type.type(:acl).provide :windows do
  #confine :feature => :microsoft_windows
  confine :operatingsystem => :windows
  defaultfor :operatingsystem => :windows

  require 'puppet/type/acl/ace'
  require 'puppet/provider/acl/windows/base'
  include Puppet::Provider::Acl::Windows::Base

  has_features :ace_order_required
  has_features :can_inherit_parent_permissions

  def initialize(value={})
    super(value)
    @property_flush = {}
    @security_descriptor = nil
  end

  def self.instances
    []
  end


  #todo def self.prefetch
  #  # not entirely sure yet if this will be needed
  #end

  def exists?
    #begin
      case @resource[:target_type]
        when :file
          # todo find the acl and determine if it exists with the identified aces
          return :true
        else
          raise Puppet::ResourceError, "At present only :target_type => :file is supported on Windows."
      end
    #rescue
    #  raise Puppet
    #end
  end

  def create
    #todo anything to go here? The DACL and security descriptor will always exist
  end

  def destroy
    #todo what are we removing? The aces listed in the dacl that would no longer be managed
  end

  def permissions
    get_current_permissions
  end

  def permissions=(value)
    non_existing_users = []
    value.each do |permission|
      non_existing_users << permission.identity unless get_account_sid(permission.identity)
    end
    raise Puppet::Error.new("Failed to set permissions for '#{non_existing_users.join(', ')}': User or users do not exist.") unless non_existing_users.empty?

    @property_flush[:permissions] = value
  end

  def permissions_insync?(current, should)
    are_permissions_insync?(current, should, @resource[:purge] == :true)
  end

  def permissions_to_s(permissions)
    return '' if permissions.nil? or !permissions.kind_of?(Array)

    perms = permissions.select { |p| !p.is_inherited}

    unless perms.nil?
      perms.each do |perm|
        perm.identity = get_account_name(perm.identity) || perm.identity
      end
    end

    perms
  end

  def owner
   get_current_owner
  end

  def owner=(value)
    raise Puppet::Error.new("Failed to set owner to '#{value}': User does not exist.") unless get_account_sid(value)

    @property_flush[:owner] = value
  end

  def owner_insync?(current, should)
    is_owner_insync?(current,should)
  end

  def owner_to_s(current_value)
    get_account_name(current_value) || current_value
  end

  def inherit_parent_permissions
    is_inheriting_permissions?
  end

  def inherit_parent_permissions=(value)
    @property_flush[:inherit_parent_permissions] = value
  end

  def flush
    sd = get_security_descriptor

    sd.owner = get_account_sid(@property_flush[:owner]) if @property_flush[:owner]

    sd.protect = resource.munge_boolean(@property_flush[:inherit_parent_permissions]) == :false if @property_flush[:inherit_parent_permissions]

    set_security_descriptor(sd) unless @property_flush.empty?

    @property_flush.clear
  end
end
