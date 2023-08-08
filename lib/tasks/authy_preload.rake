namespace :authy do

  desc 'Generate initializer file for authentication engine in parent app'
  task generate_initializer: :environment do

    initializer_content = <<~RUBY
      Rails.application.config.authy = {
        with_patient_web_app: false
      }
    RUBY

    File.open('config/initializers/authy.rb', 'w') do |file|
      file.write(initializer_content)
    end
    puts 'Initializer file generated successfully!'
  end

end
