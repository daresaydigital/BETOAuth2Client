Pod::Spec.new do |s|
  name           = "Etalio"
  url            = "https://github.com/Etalio/#{name}-Cocoa-SDK"
  git_url        = "#{url}.git"
  version        = "0.1.0"
  source_files   = "#{name}/**/*.{h,m}"

  s.name         = name
  s.version      = version
  s.summary      = "Etalio SDK for the Cocoa platform (iOS and Mac OS X)"
  s.description  = <<-DESC

                    Etalio SDK for the Cocoa platform (iOS and Mac OS X)
                    * Authenticate through Etalio
                    * Fetch profile
                    
                    DESC

  s.homepage     = url
  s.license      = 'MIT'
  s.author       = { "Seivan Heidari" => "seivan.heidari@icloud.com" }
  
  s.source       = { :git => git_url, :tag => version}
  

  s.platform  = :ios, "7.0"
  s.dependency 'SIURLSessionBlocks'

  s.source_files = source_files
  s.resources    = "#{name}/**/*.{implementation,private}"
  s.requires_arc = true
end
