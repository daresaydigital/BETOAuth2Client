Pod::Spec.new do |s|
  name           = "SIOAuth2Client"
  url            = "https://github.com/screeninteraction/#{name}"
  git_url        = "#{url}.git"
  version        = "0.1.0"
  source_files   = "#{name}/**/*.{h,m}"

  s.name         = name
  s.version      = version
  s.summary      = "Lighweight and easy to use OAuth 2 Client based on NSURLSession"
  s.description  = <<-DESC

                    OAuth 2 client for the Cocoa platform (iOS and Mac OS X)
                    * Authenticate through OAuth 2
                    * Light weight
                    * Allows for blocks or delegates
                    * Offers archivable credentials
                    * Easy to read implementation and interface
                    
                    DESC

  s.homepage     = url
  s.license      = 'MIT'
  s.author       = { "Seivan Heidari" => "seivan.heidari@screeninteraction.com",
                     "Screen Interaction" => "contact@screeninteraction.com" 
                   }
  
  s.source       = { :git => git_url, :tag => version}
  

  s.platform  = :ios, "7.0"
  s.dependency 'SIURLSessionBlocks'

  s.source_files = source_files
  s.resources    = "#{name}/**/*.{implementation,private}"
  s.requires_arc = true
end
