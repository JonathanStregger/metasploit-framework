###
#
#
# $Id$
#
# This class implements the msfvc plugin interface
# @author Jonathan Stregger
#  * *email:* (jon.stregger@gmail.com)
#
# $Revision$
#
###

require 'json'
require 'rex/text/table'
require 'getoptlong'

module Msf
  class Plugin::MsfVC < Msf::Plugin
    class MsfvcCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      def name
        'MsfVC'
      end

      def initialize(driver)
        super

        @vc_data = VCData.new
        @scripts = []
      end

      def commands
        {
          'vc_list'     => 'List available voice commands',
          'vc_details'  => 'Display details for a voice command by id or command text',
          'vc_script'   => 'Create or add to a voice command script.',
          'vc_help'     => 'Display msfvc help'
        }
      end

      def cmd_vc_script(*args)
        begin
          # Store environment arguments when get opt uses the args that will
          # be temporarily stored in ARGV
          env_args = ARGV.clone
          ARGV.clear
          args.each { |arg| ARGV << arg }
    
          opts = GetoptLong.new(
            ['--help', '-h', GetoptLong::NO_ARGUMENT],
            ['--assistant', '-a', GetoptLong::REQUIRED_ARGUMENT],
            ['--id', '-i', GetoptLong::REQUIRED_ARGUMENT],
            ['--script', '-s', GetoptLong::REQUIRED_ARGUMENT],
            ['--display', '-d', GetoptLong::NO_ARGUMENT],
            ['--remove', '-r', GetoptLong::NO_ARGUMENT],
            ['--fill', '-f', GetoptLong::REQUIRED_ARGUMENT],
            ['--modify', '-m', GetoptLong::NO_ARGUMENT],
            ['--write', '-w', GetoptLong::OPTIONAL_ARGUMENT],
            ['--load', '-l', GetoptLong::REQUIRED_ARGUMENT]
          )
          
          assistant = ''
          script = ''
          fill = []
          id = -1
          filename = ''
          options = ''
          begin
            opts.each do |opt, arg|
              case opt
              when '--help'
                usage_vc_script()
                return
              when '--assistant'
                begin
                  if (assistant = @vc_data.get_assistant(arg)).include?("\n")
                    print_line(assistant)
                    return
                  end
                rescue ArgumentError => e
                  print_error(e)
                  return
                end
              when '--script'
                script = arg
              when '--display'
                options << 'd'
              when '--remove'
                optsion << 'r'
              when '--fill'
                fill << arg
              when '--id'
                begin
                  id = Integer(arg)
                rescue ArgumentError
                  return print_error('A integer is required for id.')
                end
              when '--modify'
                options << 'm'
              when '--write'
                options << 'w'
                filename = arg if arg
              when '--load'
                return load_from_file(arg)
              end
            end
          rescue GetoptLong::Error => e
            return print_error(e)
          end
          
          return print_error('A script name is required to start or add to a script.') if script == ''

          return display_script(script) if options.include?('d')
          return write_script(script, filename) if options.include?('w')

          return print_error('A voice assistant must be specified with the -a or --assistant option or ? to list available voice assistants') if assistant == ''
          return print_error('A positive id is required to add/remove/modify voice commands in scripts.') if id < 1
          return print_error('Cannot modify and remove.') if options.include?('r') && options.include?('m')

          begin
            # Reset voice command
            if options.include?('m') && fill == []
              remove_from_script(script, assistant, id)
              add_to_script(script, assistant, id, fill)
            elsif options.include?('r')
              remove_from_script(script, assistant, id)
            elsif options.include?('m')
              mod_script(script, assistant, id, fill)
            else
              add_to_script(script, assistant, id, fill)
            end
          rescue ArgumentError => e
            print_error(e)
          end
          
        ensure
          # Restore environment arguments
          ARGV.clear
          env_args.each { |arg| ARGV << arg }
        end
      end

      def usage_vc_script()
        tbl = Rex::Text::Table.new(
          'Indent'        => 4,
          'Header'        => 'Script Voice Commands help',
          'Columns'       =>
          [
            'Option',
            'Description',
            'Example'
          ]
        )
        tbl << ['-a, --assistant', 'The voice assistant to display.', 'vc_script -a Google -i 3 -s example']
        tbl << ['-i, --id', 'The id of the voice command to add/edit/delete in the script', 'vc_script -i 4 -a Siri -s example']
        tbl << ['-d, --display', 'Display the script in its current form', 'vc_script -d -s example']
        tbl << ['-s, --script', 'The label for the script to create/modify.', 'vc_script -s example -i 4 -a Alexa']
        tbl << ['-r, --remove', 'Remove the indicated voice command from the script', 'vc_script -r -i 4 -a Siri -s example']
        tbl << ['-f, --fill', 'Fill a wildcard slot with the given argument.', 'vc_script -s example -a Siri -i 5 -f Jon -f "this is a test"']
        tbl << ['-m, --modify', 'Modify a voice command in the script. If -f is not present wildcards are reset', 'vc_script -s example -a Siri -i 5 -m']
        tbl << ['-w, --write', 'Write the script to file. Default name is the script name, but a filename can be specified.', 'vc_script -s example -w script.json']
        tbl << ['-l, --load', 'Load a script from the specified json file in the data/msfvc directory.', 'vc_script -l script.json']
        tbl << ['-h, --help', 'Show this help message', 'vc_script --help']
        print("\n#{tbl.to_s}\n")
      end

      def cmd_vc_list(*args)
        begin
          # Store environment arguments when get opt uses the args that will
          # be temporarily stored in ARGV
          env_args = ARGV.clone
          ARGV.clear
          args.each { |arg| ARGV << arg }
    
          opts = GetoptLong.new(
            ['--help', '-h', GetoptLong::NO_ARGUMENT],
            ['--assistant', '-a', GetoptLong::REQUIRED_ARGUMENT],
            ['--category', '-c', GetoptLong::REQUIRED_ARGUMENT],
            ['--search', '-s', GetoptLong::REQUIRED_ARGUMENT],
            ['--verbose', '-v', GetoptLong::NO_ARGUMENT]
          )
          
          categories = []
          search = []
          assistant = ''
          verbose = 0
          begin
            opts.each do |opt, arg|
              case opt
              when '--help'
                usage_vc_list()
                return
              when '--category'
                categories << arg.downcase
              when '--search'
                search << arg.downcase
              when '--assistant'
                begin
                  if (assistant = @vc_data.get_assistant(arg)).include?("\n")
                    print_line(assistant)
                    return
                  end
                rescue ArgumentError => e
                  print_error(e)
                  return
                end
              when '--verbose'
                verbose = 1
              end
            end
          rescue GetoptLong::Error => e
            return print_error(e)
          end
          
          return print_error('A voice assistant must be specified with the -a or --assistant option or ? to list available voice assistants') if assistant.empty?

          begin
            if verbose == 1
              print_line("\n#{@vc_data.to_s_verbose(assistant, categories, search)}")
            else
              print_line("\n#{@vc_data.to_s(assistant, categories, search)}")
            end
          rescue ArgumentError => e
            print_error(e)
          end
        ensure
          # Restore environment arguments
          ARGV.clear
          env_args.each { |arg| ARGV << arg }
        end
      end
      
      def usage_vc_list()
        tbl = Rex::Text::Table.new(
          'Indent'        => 4,
          'Header'        => 'List Voice Commands help',
          'Columns'       =>
          [
            'Option',
            'Description',
            'Example'
          ]
        )
        tbl << ['-a, --assistant', 'Required. The voice assistant to display.', 'vc_list -a Google']
        tbl << ['-c, --category', 'Add a category to filter displayed voice commands. Repeated for multiple categories. ? to list supported voice assistants', 'vc_list -a Apple -c travel -c navigation']
        tbl << ['-s, --search', 'Search for commands with some or all of the command text.', 'vc_list -a Google -s "voice mail"']
        tbl << ['-v, --verbose','Display verbose.', 'vc_list -a Siri -v']
        tbl << ['-h, --help', 'Show this help message', 'vc_list --help']
        print("\n#{tbl.to_s}\n")
      end
      
      def cmd_vc_details(*args)
        begin
          # Store environment arguments when get opt uses the args that will
          # be temporarily stored in ARGV
          env_args = ARGV.clone
          ARGV.clear
          args.each { |arg| ARGV << arg }
    
          opts = GetoptLong.new(
            ['--help', '-h', GetoptLong::NO_ARGUMENT],
            ['--assistant', '-a', GetoptLong::REQUIRED_ARGUMENT],
            ['--id', '-i', GetoptLong::REQUIRED_ARGUMENT],
            ['--search', '-s', GetoptLong::REQUIRED_ARGUMENT]
          )
          
          assistant = ''
          id = -1
          search = ''
          begin
            opts.each do |opt, arg|
              case opt
              when '--help'
                usage_vc_details()
                return
              when '--assistant'
                return if (assistant = get_assistant(arg)) == ''
              when '--search'
                if id != -1
                  print_error('Options -s and -i must not be used together.')
                  return
                else
                  search = arg
                end
              when '--id'
                if search != ''
                  print_error('Options -s and -i must not be used together.')
                  return
                else
                  begin
                    id = Integer(arg)
                    if id < 1
                      print_error('A positive integer is required for the -i option')
                      return
                    end
                  rescue ArgumentError
                    print_error('An integer is required for -i option.')
                    return
                  end
                end
              end
            end
          rescue GetoptLong::Error => e
            print_error(e)
          end

          return print_error("No options received.") if search == '' && id == -1

          if search.empty? && id != -1
            cmd = @vc_data.find_by_id(assistant, id)
          elsif !search.empty? && id == -1
            cmd = @vc_data.find_by_str(assistant, search)
            unless cmd.nil?
              if cmd.length > 2
                print_status("Found #{cmd.length} results.")
              end
              cmd = cmd[0]
              assistant = cmd.pop()
            end
          end

          if cmd.nil?
            print_error('No command found')
          else
            print_line("\n#{@vc_data.to_s_details(assistant, cmd)}")
          end
        ensure
          # Restore environment arguments
          ARGV.clear
          env_args.each { |arg| ARGV << arg }
        end
      end

      def usage_vc_details()
        tbl = Rex::Text::Table.new(
          'Indent'        => 4,
          'Header'        => 'Voice Command Details help',
          'Columns'       =>
          [
            'Option',
            'Description',
            'Example'
          ]
        )
        tbl << ['-a, --assistant', 'The voice assistant the command belongs to. Required with -i option.', 'vc_details -a Google -i 1']
        tbl << ['-i, --id', 'The id of the command being requested. Requires -a option.', 'vc_details -i 4 -a Siri']
        tbl << ['-s, --search', 'Search for a command with some or all of the command text. Returns first match.', 'vc_details -s "voice mail"']
        tbl << ['-h, --help', 'Show this help message', 'vc_details --help']
        print_line("\n#{tbl.to_s}\nNote: -i and -s may not be used together.\n")
      end

      def cmd_vc_help(*args)
        tbl = Rex::Text::Table.new(
          'Indent'  => 4,
          'Header'        => 'MsfVC Help',
          'Columns'       =>
          [
            'Command',
            'Description'
          ]
        )
        cmds = commands
        cmds.each do |cmd|
          tbl << [cmd.fetch(0), cmd.fetch(1)]
        end
        print_line("\n#{tbl.to_s}\nSee individual commands with -h or --help for details on those commands.\n")
      end

      def display_script(script)
        disp_script = get_script(script)
        unless disp_script
          print_error("#{script} script cannot be displayed. Script not found.")
          return
        end
        print_line("\n#{disp_script.to_s}")
      end

      def remove_from_script(script, assistant, id)
        return false unless rm_script = get_script(script)
        cmd = @vc_data.find_by_id(assistant, id)
        vc = VoiceCmd.new(assistant, cmd)
        rm_script.rm(vc)
      end

      def add_to_script(script, assistant, id, fill)
        # Add script to scripts list
        add_script = get_script(script) || VCScript.new(script)
        cmd = @vc_data.find_by_id(assistant, id)
        vc = VoiceCmd.new(assistant, cmd)
        unless fill == []
          begin
            vc.fill(fill)
          rescue ArgumentError
            print_error(e)
            return
          end
        end
        add_script.add(vc)
        @scripts << add_script unless get_script(script)
      end

      def mod_script(script, assistant, id, fill)
        # Add script to scripts list
        modify_script = get_script(script) || VCScript.new(script)
        cmd = find_by_id(assistant, id)
        vc = VoiceCmd.new(assistant, cmd)
        unless fill == []
          begin
            vc.fill(fill)
          rescue ArgumentError
            print_error(e)
            return
          end
        end
        if modify_script.mod(vc)
          @scripts << modify_script unless get_script(script)
        else
          print_error("Could not find voice command id #{id} in #{script} script. Script not modified.")
        end
      end
      
      def get_script(script)
        @scripts.each do |find|
          if find.name == script
            return find
          end
        end
        nil
      end

      def write_script(script, filename = '')
        write = get_script(script)
        unless write
          print_error("Could not find #{script} script. Script not written to file.")
        else
          begin
            script_path = write.save(filename)
            print_status("#{script} script written to '#{script_path}'.")
            print_error("WARNING: #{script} script contains commands that are not speech safe.") unless write.speech_safe?
          rescue IOError => e
            print_error("#{script} script not written to '#{script_path}'. #{e}")
          rescue SystemCallError => e
            print_error("#{script} script not written to '#{script_path}'. #{e}")
          rescue ArgumentError => e
            print_error(e)
          end
        end
      end

      def load_from_file(filename)
        load_script = VCScript.new('')
        begin
          load_script.read(filename)
          print_status("Script #{load_script.name} loaded from #{filename}.")
          @scripts << load_script
        rescue IOError => e
          print_error("Script not loaded from '#{filename}'. #{e}")
        rescue SystemCallError => e
          print_error("Script not loaded from '#{filename}'. #{e}")
        rescue ArgumentError => e
          print_error(e)
        rescue JSON::ParserError
          print_error("Script not loaded. '#{filename}' could not be parsed as json. Provided file must be json format.")
        end
      end
    end
    
    def name
      'msfvc'
    end
    
    def desc
      'To do'
    end
    
    def initialize(framework, opts)
      super
      
      add_console_dispatcher(MsfvcCommandDispatcher)
      
      print_status('Welcome to Voice Command by Jonathan Stregger')
      print_status("%blu                 ___        %clr")
      print_status("%blu      __ _  %red___ %blu/ _/%grn  ______%clr")
      print_status("%blu     /  ' \\%red(_-<%blu/ _/ %grn|/ / __/%clr")
      print_status("%blu    /_/_/_/%red___/%blu_/ %grn|___/\\__/ %clr")
      print_status('')
      print_status('MsfVC Version 1.0 for use with the Metasploit Framework 2020')
      print_status('For a list of commands use vc_help.')
      print_status('')
    end
    
    def cleanup
      remove_console_dispatcher('MsfVC')
    end
  end

  class VoiceCmd
    def initialize(assistant = '', cmd = [])
      if (assistant == '' || cmd == [])
        raise(ArgumentError, 'Assistant and command required for new VoiceCmd.')
      end
      @assistant = assistant
      @id = Integer(cmd[0])
      @cmd = cmd[1]['Command']
      @cat = cmd[1]['Category']
      @fill = cmd[1]['Fill notes'] || 'none'
      @purp = cmd[1]['Purpose'] || 'none'
      @vuln = cmd[1]['Vulnerability'] || 'none'
      @num_fills = @fill.count(',') + 1
    end

    def assistant
      @assistant
    end

    def id
      @id
    end

    def cmd
      @cmd
    end
    
    def cat
      @cat
    end

    def fill_notes
      @fill
    end

    def purpose
      @purp
    end

    def vuln
      @vuln
    end

    def fill(*args)
      if args.length > @num_fills
        raise(ArgumentError, "More arguments provided than wildcards to replace.")
      end
      args.each do |arg|
        # replace wildcard with argument
        @cmd = @cmd.sub(/[#\*&@:]/, arg[0])
        @num_fills -= 1
      end
      @cmd
    end

    def wildcards?
      return true if @num_fills > 0
      false
    end

    def to_s
      "Id: #{id}\nCommand: #{@cmd}\nPurpose: #{purp}\nFill notes: #{@fill}\nVulnerability: #{vuln}"
    end

    def sanitize
      @cmd = @cmd.sub(/(\/\b[a-zA-Z#\*&@:]*\b)|(\/\(.*\))/, '') while @cmd.include?('/')
      @cmd = @cmd.sub(/[\(\)]/, '') while @cmd.include?('(') || @cmd.include?(')')
      @cmd = @cmd.sub(/^\s+/, '')
    end

    def hash
      @assistant + @id.to_s
    end
  end

  class VCScript
    def initialize(script)
      @script = script
      @vc_list = []
      @assistant = ''
    end
  
    def name
      @script
    end
  
    def assistant
      @assistant
    end

    def add(add_vc)
      @assistant = add_vc.assistant if @assistant == ''
      unless @assistant == add_vc.assistant
        raise ArgumentError.new("Script #{@script} is for #{@assistant} voice commands. Recieved incompatible voice command for #{add_vc.assistant}")
      else
        @vc_list << add_vc
      end
    end
    
    def rm(rm_vc)
      @vc_list.each do |vc|
        if vc.hash == rm_vc.hash
          @vc_list.delete(vc)
          return true
        end
      end
      false
    end
  
    def mod(mod_vc)
      raise ArgumentError.new("Script #{@script} has no voice commands to modify.") unless @vc_list.length > 0
      unless @assistant == mod_vc.assistant
        raise ArgumentError.new("Script #{@script} is for #{@assistant} voice commands. Recieved incompatible voice command for #{mod_vc.assistant}")
      end
      
      index = -1
      @vc_list.each do |mod|
        if mod.hash == mod_vc.hash
          index = @vc_list.index(mod)
        end
      end

      if index != -1
        @vc_list[index] = mod_vc
        return true
      end
      
      false
    end
  
    def get_vc(assistant, id)
      hash = assistant + id.to_s
      @vc_list.each do |find|
        return find if find.hash == hash
      end
      nil
    end
  
    def speech_safe?
      @vc_list.each do |vc| 
        return false if vc.cmd.match(/[#\*&@:]/)
      end
      true
    end
    
    def save(filename)
      raise ArgumentError.new("Script '#{@script}'' not saved. No commands in script to save.") unless @vc_list.length > 0
      raise ArgumentError.new("Invalid file location. Enter filename only.") if filename.include?('/') || filename.include?('\\')

      script_hash = { "Script" => @script, "Assistant" => @assistant}
      cmds = Hash.new
      @vc_list.each do |vc|
        vc.sanitize
        cmds.store(@vc_list.index(vc) + 1,
          {"Id"           => vc.id,
          "Command"       => vc.cmd,
          "Category"      => vc.cat,
          "Fill notes"    => vc.fill_notes,
          "Purpose"       => vc.purpose,
          "Vulnerability" => vc.vuln})
      end
      script_hash.store("Commands", cmds)

      filename = @script.dup if filename == ''
      filename << '.json' unless (filename.include?('.json'))
      script_path = File.join(Msf::Config.data_directory, 'msfvc', filename)
      File.open(script_path, 'w') do |fp|
        fp.write(JSON.pretty_generate(script_hash))
      end
      script_path
    end

    def read(filename)
      raise ArgumentError.new("Invalid file location. Enter filename only.") if filename.include?('/') || filename.include?('\\')
      script_path = File.join(Msf::Config.data_directory, 'msfvc', filename)
      script_data = JSON.parse(File.read(script_path))
      @script = script_data['Script']
      @assistant = script_data['Assistant']
      
      raise ArgumentError.new("Unable to load script. JSON file does not have required fields for a vc script.") if script_data.nil? || @script.nil? || @assistant.nil?
      
      script_data['Commands'].each do |cmd|
        id = cmd[1]['Id']
        cmd[1].delete('Id')
        load_cmd = [id, cmd[1]]
        @vc_list << VoiceCmd.new(@assistant, load_cmd)
      end
    end

    def to_s()
      tbl = Rex::Text::Table.new(
          'Indent'        => 4,
          'Header'        => "Script #{@script} for #{@assistant}",
          'Columns'       =>
          [
            'Index',
            'Id',
            'Command'
          ]
        )
      @vc_list.each do |vc|
        tbl << [ @vc_list.index(vc), vc.id, vc.cmd ]
      end
      tbl.to_s
    end
  end
  
  class VCData
    def initialize(filename = 'voice-commands.json')
      vc_json_path = File.join(Msf::Config.data_directory, 'wordlists', filename)
      @vc_data = JSON.parse(File.read(vc_json_path))
    end
    
    def to_s(assistant, category = [], search = [])
      cmds = find_by_str(assistant, search)
      
      tbl = Rex::Text::Table.new(
        'Indent'  => 4,
        'Header'  => "#{assistant} Voice Commands",
        'Columns' =>
        [
          'id',
          'Command',
          'Category'
        ]
      )
      unless cmds.nil?
        puts(cmds.inspect)
        cmds.each do |cmd|
          if category.empty? || category.include?(cmd[1]['Category'])
            tbl << [cmd[0],
                    cmd[1]['Command'],
                    cmd[1]['Category']]
          end
        end
      else
        @vc_data[assistant].each do |cmd|
          if category.empty? || category.include?(cmd[1]['Category'])
            tbl << [cmd[0],
                    cmd[1]['Command'],
                    cmd[1]['Category']]
          end
        end
      end
      tbl.to_s
    end

    def to_s_verbose(assistant, category = [], search = [])
      cmds = find_by_str(assistant, search)

      tbl = Rex::Text::Table.new(
        'Indent'  => 4,
        'Header'  => "#{assistant} Voice Commands",
        'Columns' =>
        [
          'id',
          'Command',
          'Category',
        'Fill Notes',
        'Purpose',
        'Vulnerability'
        ]
      )
      unless cmds.nil?
        cmds.each do |cmd|
          if category == [] ||
            category.include?(cmd[1]['Category'])
            tbl << [cmd[0],
                    cmd[1]['Command'],
                    cmd[1]['Category'],
                    cmd[1]['Fill notes'] || 'none',
                    cmd[1]['Purpose'] || 'none',
                    cmd[1]['Vulnerability'] || 'none']
          end
        end
      else
        @vc_data[assistant].each do |cmd|
          if category == [] || category.include?(cmd[1]['Category'])
            tbl << [cmd[0],
                    cmd[1]['Command'],
                    cmd[1]['Category'],
                    cmd[1]['Fill notes'] || 'none',
                    cmd[1]['Purpose'] || 'none',
                    cmd[1]['Vulnerability'] || 'none']
          end
        end
      end
      tbl.to_s
    end
    
    def to_s_details(assistant, cmd)
      msg = "#{assistant} Voice Command\n"
      (msg.length - 1).times do
        msg << '='
      end
      msg << "\n\n    Id:\n#{details_line(cmd[0])}\n\n"
      msg << "    Command:\n#{details_line(cmd[1]['Command'])}\n\n"
      msg << "    Fill notes:\n#{details_line(cmd[1]['Fill notes'])}\n\n"
      msg << "    Purpose:\n#{details_line(cmd[1]['Purpose'])}\n\n"
      msg << "    Vulnerability:\n#{details_line(cmd[1]['Vulnerability'])}\n\n"
    end
    
    def find_by_id(assistant, id)
      raise ArgumentError.new('Cannot find by id. Assistant must be specified to search by id.') if assistant.empty?
      
      @vc_data[assistant].each do |cmd|
        if cmd[0].to_i == id
          return cmd
        end
      end
      nil
    end
    
    def find_by_str(assistant, terms = [])
      return [] if terms.empty?

      cmds = []
      terms.each do |search|
      search = search.downcase
        unless assistant.empty?
          @vc_data[assistant].each do |cmd|
            if cmd[1]['Command'].include?(search) ||
              check_search(cmd[1]['Category'], search) ||
              check_search(cmd[1]['Fill notes'], search) ||
              check_search(cmd[1]['Purpose'], search) ||
              check_search(cmd[1]['Vulnerability'], search)
              cmd << assistant
              cmds << cmd
            end
          end
        else
          assistants = @vc_data.keys
          assistants.each do |assistant|
            @vc_data[assistant].each do |cmd|
              if cmd[1]['Command'].include?(search) ||
                check_search(cmd[1]['Category'], search) ||
                check_search(cmd[1]['Fill notes'], search) ||
                check_search(cmd[1]['Purpose'], search) ||
                check_search(cmd[1]['Vulnerability'], search)
                cmd << assistant
                cmds << cmd
              end
            end
          end
        end
      end

      return cmds unless cmds.empty?
      nil
    end
    
    def get_assistant(assistant)
      if assistant == '?'
        supported = "\nSupported voice assistants\n==========================\n"
        supported_vas = @vc_data.keys
        supported_vas.each do |va|
          supported << "    #{va}\n"
        end
        return supported
      end

      test_case = assistant.downcase
      test_case = test_case.sub(/^hey /,'')
      @vc_data.keys.each do |va|
        if va.downcase.include?(test_case.downcase)
          return va
        end
      end
      
      raise ArgumentError.new("#{assistant} is not a supported voice assistant.")
    end

    private
    def check_search(obj, search)
      if obj.nil?
        return false
      end
      obj.include?(search)
    end
    
    def details_line(str)
      if str.nil?
        return '     none'
      end
      '     ' << str.capitalize
    end
  end
end

