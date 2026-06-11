require 'simplecov-cobertura'

SimpleCov.formatter = SimpleCov::Formatter::CoberturaFormatter

# Coverage is measured for the scanner only — test/coverage.sh drives it through every branch.
SimpleCov.configure do
  add_filter { |source_file| !source_file.filename.include?('/src/') }
end
SimpleCov.minimum_coverage 85
