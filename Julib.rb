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
    /['"]\b[A-Z]{5}-[0-9]{4}-[a-z]{5}-[A-Z]{5}\b['"]/,
  ],
  aws_access_key_pattern: [
    /['"]\bAKIA[0-9A-Z]{16}\b['"]/,
    /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/
  ],
  azure_api_key_pattern: [
    /['"]\b[A-Za-z0-9]{32}\.Azure\.API\.Key['"]/
  ],
  github_api_key_pattern: [
    /['"]\b[a-z0-9]{40}\b['"]/,
    /['"]\b[A-Z0-9]{35,40}\b['"]/,
    /(ghu|ghs)_[0-9a-zA-Z]{36}/,
    /github_pat_[0-9a-zA-Z_]{82}/,
    /gho_[0-9a-zA-Z]{36}/,
    /ghp_[0-9a-zA-Z]{36}/,
    /ghr_[0-9a-zA-Z]{36}/,
    /glpat-[0-9a-zA-Z\-\_]{20/,
    /glptt-[0-9a-f]{40}/,
    /GR1348941[0-9a-zA-Z\-\_]{20}/,
    /(?i)(?:gitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9_-]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)/,
  ],
  google_api_key_pattern: [
    /['"]\bAIza[0-9A-Za-z_-]{35}\b['"]/,
    /AIza[0-9A-Za-z\\-_]{35}/,
    /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/,
    /(?i)\bAIza[0-9A-Za-z\\-_]{35}\b/
  ],
  facebook_api_key_pattern: [
    /['"]\b\d{15,16}\|.{27}\b['"]/,
    /EAACEdEose0cBA[0-9A-Za-z]+/,
    /(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}/,
    /(?i)facebook.*['|\"]\w{140}['|\"]/,
    /(?i)(?:facebook)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)/
  ],
  twitter_api_key_pattern: [
    /['"][1-9][0-9]{5,}[a-zA-Z0-9]{25,}['"]/
  ],
  slack_api_key_pattern: [
    /['"]xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}['"]/,
    /(?i)slack.*['|\"]xox[baprs]-\w{12}-\w{12}-\w{12}['|\"]/
  ],
  stripe_api_key_pattern: [
    /['"]sk_test_[0-9a-zA-Z]{24}['"]/,
    /['"]rk_test_[0-9a-zA-Z]{24}['"]/,
    /(?i)(sk|pk)_(test|live)_[0-9a-z]{10,32}/
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
    /['"]AIza[0-9A-Za-z_-]{35}['"]/,
    /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/
  ],
  digitalocean_api_key_pattern: [
    /['"]\b[a-zA-Z0-9_-]{64}\b['"]/
  ],
  heroku_api_key_pattern: [
    /['"]\b[a-zA-Z0-9_-]{64}\b['"]/,
    /(?i)heroku.*['|\"]\w{32}['|\"]/
  ],
  mongodb_atlas_api_key_pattern: [
    /['"]\b[a-zA-Z0-9_-]{36}\b['"]/,
    /['"]\b[A-Za-z0-9]{20}\.[A-Za-z0-9]{20}\b['"]/,
    /['"]\b[A-Za-z0-9_-]{50,100}\b['"]/
  ],
  rapidapi_key_pattern: [
    /['"]\b[a-zA-Z0-9_-]{32}\b['"]/
  ],
  artifactory_api_token: [
    /(?:\s|=|:|^|"|&)AKC[a-zA-Z0-9]{10,}/
  ],
  cloudinary: [
    /cloudinary:\/\/[0-9]{15}:[0-9A-Za-z]+@[a-z]+/
  ],
  email: [
    /(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z.-]+/,
    /([a-zA-Z0-9][_\.\w]*)+@([a-zA-Z0-9][\w\-]*\.[a-zA-Z]{2,})\b(?:(?:(?i)js|css|jpg|jpeg|png|ico)\b\\1)*/
  ],
  pgp_private_key_block: [
    /-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----/m
  ],
  ssh_private_key: [
    /-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----.+?-----END (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----/m
  ],
  ssh_public_key: [
    /ssh-ed25519\s+[A-Za-z0-9\/+=]+\s+[^\n]+/
  ],
  amazon_mws_auth_token: [
    /['"]\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b['"]/
  ],
  authorization_basic_credentials: [
    /Basic\s+[A-Za-z0-9_=-]+/
  ],
  authorization_bearer_token: [
    /Bearer\s+[A-Za-z0-9_=-]+/
  ],
  jwt_token_pattern: [
    /Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/
  ],
  windows_live_api_key: [
    /(?i)windowslive.*['|\"][0-9a-f]{22}['|\"]/
  ],
  bitcoin_private_key_pattern: [
    /[5KL][1-9A-HJ-NP-Za-km-z]{51}/,
    /[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$/
  ],
  ethereum_private_key:[
    /0x[a-fA-F0-9]{64}/
  ],
  ripple_secret_key: [
    /['"]s[a-zA-Z0-9]{53}\b['"]/
  ],
  litecoin_private_key_wif: [
    /['"][LK][1-9A-HJ-NP-Za-km-z]{50}\b['"]/
  ],
  bitcoin_cash_private_key_wif: [
    /['"][Kk][1-9A-HJ-NP-Za-km-z]{50,51}\b['"]/
  ],
  cardano_extended_private_key: [
    /['"]xprv[a-zA-Z0-9]{182}\b['"]/
  ],
  monero_private_spend_key: [
    /['"]4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b['"]/
  ],
  monero_private_view_key: [
    /['"]9[1-9A-HJ-NP-Za-km-z]{94}\b['"]/
  ],
  zcash_private_key: [
    /['"]sk[a-zA-Z0-9]{95}\b['"]/
  ],
  tezos_secret_key: [
    /['"]edsk[a-zA-Z0-9]{54}\b['"]/
  ],
  eos_private_key: [
    /['"]5[a-zA-Z0-9]{50}\b['"]/
  ],
  stellar_secret_key: [
    /['"]S[a-zA-Z0-9]{55}\b['"]/
  ],
  neo_private_key: [
    /['"]K[a-zA-Z0-9]{51}\b['"]/
  ],
  iota_seed: [
    /['"][A-Z9]{81}\b['"]/
  ],
  tron_private_key: [
    /['"]0x[a-fA-F0-9]{64}\b['"]/
  ],
  vechain_private_key: [
    /['"]0x[a-fA-F0-9]{64}\b['"]/
  ],
  avalanche_private_key: [
    /['"]PrivateKey-[a-zA-Z0-9]{58}\b['"]/
  ],
  polkadot_private_key: [
    /['"]0x[a-fA-F0-9]{64}\b['"]/
  ],
  chainlink_private_key: [
    /['"]0x[a-fA-F0-9]{64}\b['"]/
  ],
  cosmos_private_key: [
    /['"]0x[a-fA-F0-9]{64}\b['"]/
  ],
  filecoin_private_key: [
    /['"]f1[a-zA-Z0-9]{98}\b['"]/
  ],
  algorand_private_key: [
    /['"]([A-Z2-7]{58})\b['"]/
  ],
  near_protocol_private_key: [
  /['"]([0-9a-fA-F]{64})['"]/
  ],
  hedera_hashgraph_private_key: [ 
    /302e020100300506032b657004220420[a-fA-F0-9]{64}300506032b657001020420[a-fA-F0-9]{64}$/ 
  ],
  circleci: [ 
    /(?i)circleci.*['|\"]\w{40}['|\"]/ 
  ],
  hootsuite: [ 
    /(?i)hootsuite.*['|\"]\w{12}['|\"]/ 
  ],
  twitch: [ 
    /(?i)twitch(.{0,20})?['\"][0-9a-z]{30}['\"]/,
    /oauth:[a-z0-9]+/
  ],
  salesforce: [ 
    /(?i)salesforce.*['|\"]\w{300}['|\"]/ 
  ],
  zoho: [ 
    /(?i)zoho.*['|\"]\w{32}['|\"]/ 
  ],
  asana: [ 
    /(?i)asana.*['|\"]\w{64}['|\"]/ 
  ],
  git: [ 
    /(?i)git.*['|\"]\w{40}['|\"]/ 
  ],
  splunk: [ 
    /(?i)splunk.*token\s*:\s*['|\"]\w{32}['|\"]/ 
  ],
  harmony_private_key: [
  /['"]0x[a-fA-F0-9]{64}\b['"]/,
  /one1[a-zA-Z0-9]{38}$/
  ],
  harmony_bls_key: [
  /['"]bls[a-zA-Z0-9]{86}\b['"]/,
  /one1p[a-zA-Z0-9]{55}$/
  ],
  mysql_connection_pattern: [
  /mysql:\/\/[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+/
  ],
  zendesk_secret_key: [
    /(?i)(?:zendesk)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)/
  ],
  yandex_aws_access_token: [
    /(?i)(?:yandex)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(YC[a-zA-Z0-9_\-]{38})(?:['|\"|\n|\r|\s|\x60|;]|$)/
  ],
  yandex_api_key: [
    /(?i)(?:yandex)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(AQVN[A-Za-z0-9_\-]{35,38})(?:['|\"|\n|\r|\s|\x60|;]|$)/
  ],
  okta_access_token: [
    /(?i)(?:okta)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{42})(?:['|\"|\n|\r|\s|\x60|;]|$)/
  ],
  pypi_upload_token: [
    /pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}/
  ],
  lob_api_key: [
    /(?i)(?:lob)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}((live|test)_[a-f0-9]{35})(?:['|\"|\n|\r|\s|\x60|;]|$)/
  ],
  lob_publishable_api_key: [
    /(?i)(?:lob)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}((test|live)_pub_[a-f0-9]{31})(?:['|\"|\n|\r|\s|\x60|;]|$)/
  ],
  gcp_api_key: [
    /(?i)\b(AIza[0-9A-Za-z\\-_]{35})(?:['|\"|\n|\r|\s|\x60|;]|$)/
  ],
  generic_api_key: [
    /(?i)(api_key|apikey|secret)(.{0,20})?['|"][0-9a-zA-Z]{16,45}['|"]/
  ],
  age_secret_key: [
    /AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}/
  ],
  clojars_api_token: [
    /(?i)(CLOJARS_)[a-z0-9]{60}/
  ],
  doppler_api_token: [
    /(dp\.pt\.)(?i)[a-z0-9]{43}/
  ],
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

# Function to clean and validate URLs
def clean_and_validate_urls(url_list)
  valid_urls = []
  url_list.each do |line|
    line.split(',').each do |url|
      url.strip!
      begin
        uri = URI.parse(url)
        if uri.kind_of?(URI::HTTP) || uri.kind_of?(URI::HTTPS)
          valid_urls << url
        else
          puts "Invalid URL format: #{url}"
        end
      rescue URI::InvalidURIError
        puts "Invalid URL format: #{url}"
      end
    end
  end
  valid_urls
end

# Function to scan a web page for API keys
def scan_web_page(url, patterns, verbose)
  begin
    page_content = URI.open(url, "User-Agent" => "Mozilla/5.0").read
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
    valid_urls = clean_and_validate_urls(urls)
    File.open(output_file, 'w') if output_file
    all_keys = []
    valid_urls.each do |url|
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
