module Ahoy
  class MessagesController < ActionController::Base
    around_action :use_write_database

    if respond_to? :before_action
      before_action :set_message
    else
      before_filter :set_message
    end

    def open
      if @message && !@message.opened_at
        @message.opened_at = Time.now
        @message.save!
      end
      publish :open
      send_data Base64.decode64("R0lGODlhAQABAPAAAAAAAAAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw=="), type: "image/gif", disposition: "inline"
    end

    def click
      # Don't redirect if the message is missing or the sender was locked for spam
      return redirect_to 'https://traveljoy.com/404.html' if @message.blank? || user_locked_for_spam?

      if @message && !@message.clicked_at
        @message.clicked_at = Time.now
        @message.opened_at ||= @message.clicked_at
        @message.save!
      end
      url = params[:url].to_s
      signature = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new("sha1"), AhoyEmail.secret_token, url)
      publish :click, url: params[:url]
      if secure_compare(params[:signature].to_s, signature)
        redirect_to url
      else
        redirect_to AhoyEmail.invalid_redirect_url || main_app.root_url
      end
    end

    protected

    def set_message
      @message = AhoyEmail.message_model.where(token: params[:id]).first
    end

    def publish(name, event = {})
      AhoyEmail.subscribers.each do |subscriber|
        if subscriber.respond_to?(name)
          event[:message] = @message
          event[:controller] = self
          subscriber.send name, event
        end
      end
    end

    # from https://github.com/rails/rails/blob/master/activesupport/lib/active_support/message_verifier.rb
    # constant-time comparison algorithm to prevent timing attacks
    def secure_compare(a, b)
      return false unless a.bytesize == b.bytesize

      l = a.unpack "C#{a.bytesize}"

      res = 0
      b.each_byte { |byte| res |= byte ^ l.shift }
      res == 0
    end

    private
    def use_write_database
      ActiveRecord::Base.connected_to(role: :writing) do
        yield if block_given?
      end
    end

    def user_locked_for_spam?
      @message.user.user.suspected_spammer?
    end
  end
end
