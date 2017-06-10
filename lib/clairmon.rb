#!/usr/bin/env ruby

require 'net/http'
require 'json'

class Clairmon
  def initialize(tls=true, baseUrl, accesKey, accessSecret, imageIgnoreArray, clairctlBinary, clairctlConfigPath)
     @TLS                   = tls
     @BASE_URL              = baseUrl
     @ACCESS_KEY            = accesKey
     @ACCESS_SECRET         = accessSecret
     @IMAGE_IGNORE_ARRAY    = imageIgnoreArray
     @CLAIRCTL_CONFIG_PATH  = clairctlConfigPath
     @CLAIRCTL_BINARY       = clairctlBinary
  end

  def getRunningImages
    if @TLS == false
      uri = URI("http://#{@BASE_URL}/v2-beta/containers")
    else
      uri = URI("https://#{@BASE_URL}/v2-beta/containers")
    end

    req = Net::HTTP::Get.new(uri)
    req.basic_auth @ACCESS_KEY, @ACCESS_SECRET

    res = Net::HTTP.start(uri.hostname, uri.port) {|http|
      http.request(req)
    }

    response_json = JSON.parse(res.body)

    runningImages = []

    response_json["data"].each do |con|
      runningImages << con["imageUuid"].sub("docker:", "")
    end

    return runningImages.uniq
  end

  def scanImage(imageName)
    value = %x[#{@CLAIRCTL_BINARY} analyze #{imageName} --config #{@CLAIRCTL_CONFIG_PATH}]

    parsedValue     = value.split("\n")
    vulnerabilities = 0

    parsedValue.each do |line|
      if line.include? "Analysis"
        parsedValueLine = parsedValue.to_a[4].split(" ").to_a
        vulnerabilities += parsedValueLine[4].to_i
      end
    end

    return vulnerabilities
  end

  def createReport(imageName)
    value = %x[#{@CLAIRCTL_BINARY} report #{imageName} --config #{@CLAIRCTL_CONFIG_PATH}]

    return value
  end

  def ignored(imageName)
    skip = false
    @IMAGE_IGNORE_ARRAY.each do |imageIgnore|
      if imageName.include? imageIgnore
        skip = true
        break
      end
    end

    return skip
  end

  def getFullStatus
    runningImagesArray = []
    self.getRunningImages.each do |scan|
      if self.ignored(scan) == false
        vuns = self.scanImage(scan)
        runningImagesArray << { 'image' => scan, 'vulnerabilities' => vuns }
      end
    end

    return runningImagesArray
  end

end
