require 'optparse'
require 'open-uri'

# ASCII art representation of text "API Key Scanner"
ASCII_ART = <<-ART
      _           _   _   _     
     | |  _   _  | | (_) | |__  
  _  | | | | | | | | | | | '_ \\ 
 | |_| | | |_| | | | | | | |_) |
  \\___/   \\__,_| |_| |_| |_.__/ 
                               

ART

puts ASCII_ART

# Define patterns to search for
API_KEY_PATTERNS = {
  synchronous: [
    /['"]\b[A-Za-z0-9]{32}\b['"]/,
    /['"]\b[A-Za-z0-9_]{24}\b['"]/,
    /['"]\b[0-9a-f]{32}\b['"]/,
    /['"]\b[0-9a-f]{40}\b['"]/,
    /['"]\b[0-9a-f]{64}\b['"]/
  ],
  asynchronous: [
    /['"]\b[0-9a-zA-Z_-]{39}\b['"]/
  ],
  another_pattern: [
    /['"]\b[0-9A-Za-z_-]{20,50}\b['"]/,
    /['"]\b[A-Z0-9]{10,30}\b['"]/
  ],
  custom_pattern: [
    /['"]\b[0-9a-fA-F]{32}-[0-9a-fA-F]{16}\b['"]/,
    /['"]\b[A-Z]{5}-[0-9]{4}-[a-z]{5}-[A-Z]{5}\b['"]/
  ],
  secret_token_pattern: [
    /['"]\b[0-9a-zA-Z]{20}\b['"]/,
    /['"]\b[A-Z]{5}-[0-9]{4}-[a-z]{5}-[A-Z]{5}\b['"]/
  ],
  aws_access_key_pattern: [
    /['"]\bAKIA[0-9A-Z]{16}\b['"]/
  ],
  azure_api_key_pattern: [
    /['"]\b[A-Za-z0-9]{32}\.Azure\.API\.Key['"]/
  ],
  github_api_key_pattern: [
    /['"]\b[a-z0-9]{40}\b['"]/,
    /['"]\b[A-Z0-9]{35,40}\b['"]/
  ],
  google_api_key_pattern: [
    /['"]\bAIza[0-9A-Za-z_-]{35}\b['"]/
  ],
  facebook_api_key_pattern: [
    /['"]\b\d{15,16}\|.{27}\b['"]/
  ],
  twitter_api_key_pattern: [
    /['"][1-9][0-9]{5,}[a-zA-Z0-9]{25,}['"]/
  ],
  slack_api_key_pattern: [
    /['"]xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}['"]/
  ],
  stripe_api_key_pattern: [
    /['"]sk_test_[0-9a-zA-Z]{24}['"]/,
    /['"]rk_test_[0-9a-zA-Z]{24}['"]/
  ],
  twilio_api_key_pattern: [
    /['"]SK[0-9a-fA-F]{32}\b['"]/
  ],
  sendgrid_api_key_pattern: [
    /['"]SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{22}['"]/
  ],
  mailgun_api_key_pattern: [
    /['"]key-[0-9a-zA-Z]{32}['"]/
  ],
  firebase_api_key_pattern: [
    /['"]AIza[0-9A-Za-z_-]{35}['"]/
  ],
  digitalocean_api_key_pattern: [
    /['"]\b[a-zA-Z0-9_-]{64}\b['"]/
  ],
  heroku_api_key_pattern: [
    /['"]\b[a-zA-Z0-9_-]{64}\b['"]/
  ],
  mongodb_atlas_api_key_pattern: [
    /['"]\b[a-zA-Z0-9_-]{36}\b['"]/
  ],
  rapidapi_key_pattern: [
    /['"]\b[a-zA-Z0-9_-]{32}\b['"]/
  ]
}

# Function to search for API keys in a string
def find_api_keys(text, patterns)
  keys = []
  patterns.each do |pattern|
    keys += text.scan(pattern)
  end
  keys
end

# Function to scan a JavaScript file for API keys
def scan_js_file(file_path, patterns, verbose)
  begin
    contents = File.read(file_path)
    keys_found = {}
    patterns.each do |key_type, key_patterns|
      keys = find_api_keys(contents, key_patterns)
      keys_found[key_type] = keys.uniq unless keys.empty?
    end
    keys_found.each do |key_type, keys|
      keys.each do |key|
        puts "Potential #{key_type.to_s.capitalize} API key found in #{file_path}: #{key}" if verbose
      end
    end
    keys_found.values.flatten
  rescue => e
    puts "Error scanning #{file_path}: #{e.message}"
    []
  end
end

# Function to scan a web page for API keys
def scan_web_page(url, patterns, verbose)
  begin
    page_content = URI.open(url, "User-Agent" => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36").read
    keys_found = {}
    patterns.each do |key_type, key_patterns|
      keys = find_api_keys(page_content, key_patterns)
      keys_found[key_type] = keys.uniq unless keys.empty?
    end
    keys_found.each do |key_type, keys|
      keys.each do |key|
        puts "Potential #{key_type.to_s.capitalize} API key found in #{url}: #{key}" if verbose
      end
    end
    keys_found.values.flatten
  rescue => e
    puts "Error scanning #{url}: #{e.message}"
    []
  end
end

# Function to scan multiple web pages from a file
def scan_web_pages_from_file(file_path, patterns, verbose, output_file=nil)
  begin
    urls = File.readlines(file_path).map(&:strip)
    File.open(output_file, 'w') if output_file
    all_keys = []
    urls.each do |url|
      keys = scan_web_page(url, patterns, verbose)
      all_keys.concat(keys)
      File.write(output_file, "Potential API keys found in #{url}: #{keys}\n", mode: 'a') if output_file
    end
    all_keys
  rescue => e
    puts "Error scanning URLs from file #{file_path}: #{e.message}"
    []
  end
end

if options ||= {}
  OptionParser.new do |opts|
    opts.banner = "Usage: ruby Julib.rb [options]"

    opts.on("-f", "--file FILE", "File containing URLs to scan") do |file|
      options[:file] = file
    end

    opts.on("-v", "--verbose", "Print verbose output") do
      options[:verbose] = true
    end

    opts.on("-o", "--output FILE", "Output file to store results") do |output_file|
      options[:output_file] = output_file
    end
  end.parse!

  # Trap Ctrl+C and Control character signals
  Signal.trap("INT") { puts "\nInterrupted by Ctrl+C"; exit }
  Signal.trap("TERM") { puts "\nTerminated by Control character"; exit }

  if options[:file]
    scan_web_pages_from_file(options[:file], API_KEY_PATTERNS, options[:verbose], options[:output_file])
  else
    puts "Please specify a file containing URLs to scan."
  end
end
