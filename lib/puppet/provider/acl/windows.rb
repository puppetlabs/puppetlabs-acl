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

  #def self.prefetch
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
    @property_flush[:permissions] = value
  end

  def owner
   get_current_owner
  end

  def owner=(value)
    @property_flush[:owner] = value
  end

  def owner_insync?(current, should)
    is_owner_insync?(current,should)
  end

  def owner_to_s(current_value)
    get_account_name(current_value)
  end

  def inherit_parent_permissions
    is_inheriting_permissions?
  end

  def inherit_parent_permissions=(value)
    @property_flush[:inherit_parent_permissions] = value
  end

  def flush
    #todo implement setters for each
    # set OWNER FIRST
    # set permissions
    # last set inherit parent perms
  end
end
