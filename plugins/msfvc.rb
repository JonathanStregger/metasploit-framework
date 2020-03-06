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

        vc_json_path = File.join(Msf::Config.data_directory, 'wordlists', 'voice-commands.json')
        @vc_data = JSON.parse(File.read(vc_json_path))

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
            ['--write', '-w', GetoptLong::OPTIONAL_ARGUMENT]
          )
          
          assistant = ''
          script = ''
          display = 0
          remove = 0
          fill = []
          id = -1
          modify = 0
          write = 0
          filename = ''
          begin
            opts.each do |opt, arg|
              case opt
              when '--help'
                usage_vc_script()
                return
              when '--assistant'
                return if (assistant = get_assistant(arg)) == ''
              when '--script'
                script = arg
              when '--display'
                display = 1
              when '--remove'
                remove = 1
              when '--fill'
                fill << arg
              when '--id'
                begin
                  id = Integer(arg)
                rescue ArgumentError
                  print_error('A integer is required for id.')
                  return
                end
              when '--modify'
                modify = 1
              when '--write'
                write = 1
                filename = arg if arg
              end
            end
          rescue GetoptLong::Error => e
            print_status("#{e}")
          end
          
          if script == ''
            print_error('A script name is required to start or add to a script.')
            return if display == 1 || assistant != ''
          end

          return display_script(script) if display == 1
          return write_script(script, filename) if write == 1

          return print_error('A voice assistant must be specified with the -a or --assistant option or ? to list available voice assistants') if assistant == ''
          return print_error('A positive id is required to add/remove/modify voice commands in scripts.') if id < 1
          return print_error('Cannot modify and remove.') if remove == 1 && modify == 1

          begin
            # Reset voice command
            if modify == 1 && fill == []
              remove_from_script(script, assistant, id)
              add_to_script(script, assistant, id, fill)
            elsif remove == 1
              remove_from_script(script, assistant, id)
            elsif modify == 1
              mod_script(script, assistant, id, fill)
            else
              add_to_script(script, assistant, id, fill)
            end
          rescue ArgumentError => e
            print_error(e.message)
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
        tbl << ['-w, -write', 'Write the script to file. Default name is the script name, but a filename can be specified.', 'vc_script -s example -w script.json']
        tbl << ['-h, --help', 'Show this help message', 'vc_list --help']
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
                return if (assistant = get_assistant(arg)) == ''
              when '--verbose'
                verbose = 1
              end
            end
          rescue GetoptLong::Error => e
            print_status("#{e}")
          end
          
          if assistant == ''
            print_error('A voice assistant must be specified with the -a or --assistant option or ? to list available voice assistants')
            return
          end

          cmds = []
          if search != []
            search.each do |term|
              cmds << find_by_str(assistant, term)
            end
            if cmds == [[]]
              print_error("No match found.")
              return
            end
          end

          if verbose == 1
            display_verbose(assistant, categories, cmds)
          else
            display(assistant, categories, cmds)
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
            print_status("#{e}")
          end

          if search == '' && id != -1
            cmd = find_by_id(assistant, id)
          elsif search != '' && id == -1
            cmd = find_by_str(assistant, search)
            if cmd != []
              if cmd.length > 2
                print_status("Found #{cmd.length} results.")
              end
              cmd = cmd[0]
              assistant = cmd.pop()
            end
          end

          if cmd == []
            print_error('No command found')
          else
            details(assistant, cmd)
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

      def details(assistant, cmd)
        msg = "#{assistant} Voice Command\n"
        (msg.length - 1).times do
          msg << '='
        end
        msg << "\n\n    Id:\n#{details_line(cmd[0])}\n\n"
        msg << "    Command:\n#{details_line(cmd[1]['Command'])}\n\n"
        msg << "    Fill notes:\n#{details_line(cmd[1]['Fill notes'])}\n\n"
        msg << "    Purpose:\n#{details_line(cmd[1]['Purpose'])}\n\n"
        msg << "    Vulnerability:\n#{details_line(cmd[1]['Vulnerability'])}\n\n"
        print_line("\n#{msg}")
      end

      def details_line(str)
        if str.nil?
          return '    none'
        end
        str = '    ' << str.capitalize
      end

      def display(provider, category = [], cmds = [])
        tbl = Rex::Text::Table.new(
          'Indent'  => 4,
          'Header'  => "#{provider} Voice Commands",
          'Columns' =>
          [
            'id',
            'Command',
            'Category'
          ]
        )
        if cmds != []
          cmds[0].each do |cmd|
            if category == [] ||
              category.include?(cmd.fetch(1)['Category'])
              tbl << [cmd.fetch(0),
                      cmd.fetch(1)['Command'],
                      cmd.fetch(1)['Category']]
            end
          end
        else
          @vc_data[provider].each do |cmd|
            if category == [] ||
              category.include?(cmd.fetch(1)['Category'])
              tbl << [cmd.fetch(0),
              cmd.fetch(1)['Command'],
              cmd.fetch(1)['Category']]
            end
          end
        end
        print("\n#{tbl.to_s}\n")
      end

      def display_verbose(provider, category = [], cmds = [])
        tbl = Rex::Text::Table.new(
          'Indent'  => 4,
          'Header'  => "#{provider} Voice Commands",
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
        if cmds != []
          cmds.each do |cmd|
            if category == [] ||
              category.include?(cmd.fetch(1)['Category'])
              tbl << [cmd.fetch(0),
                      cmd.fetch(1)['Command'],
                      cmd.fetch(1)['Category'],
                      cmd.fetch(1)['Fill notes'],
                      cmd.fetch(1)['Purpose'],
                      cmd.fetch(1)['Vulnerability']]
            end
          end
        else
          @vc_data[provider].each do |cmd|
            if category == [] || category.include?(cmd.fetch(1)['Category'])
              tbl << [cmd.fetch(0),
                      cmd.fetch(1)['Command'],
                      cmd.fetch(1)['Category'],
                      cmd.fetch(1)['Fill notes'],
                      cmd.fetch(1)['Purpose'],
                      cmd.fetch(1)['Vulnerability']]
            end
          end
        end
        print("\n#{tbl.to_s}\n")
      end

      def get_assistant(arg)
        arg = arg.downcase
        if arg == 'google' || arg == 'hey google' || arg == "google voice assistant"
          return 'Google voice assistant'
        elsif arg == 'siri' || arg == 'hey siri' || arg == 'apple'
          return 'Apple Siri'
        elsif arg == 'alexa' || arg == 'amazon'
          return 'Amazon Alexa'
        elsif arg == '?'
          print_line("\nSupported voice assistants")
          print_line("==========================\n")
          vas = @vc_data.keys
          vas.each do |va|
            print_line("    #{va}")
          end
          print_line('')
          return ''
        else
          print_error("#{arg} is not a supported voice assistant.")
          return ''
        end
      end

      def find_by_id(assistant, id)
        if assistant == ''
          print_error('Assistant must be provided with -a when using -i.')
          return []
        end
        @vc_data[assistant].each do |cmd|
          if cmd.fetch(0).to_i == id
            return cmd
          end
        end
        []
      end

      def find_by_str(assistant, search)
        search = search.downcase
        cmds = []
        if assistant != ''
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
        cmds
      end

      def check_search(obj, search)
        if obj.nil?
          return false
        end
        obj.include?(search)
      end

      def display_script(script)
        disp_script = get_script(script)
        unless disp_script
          print_error("'#{script}' cannot be displayed. Script not found.")
          return
        end
        print_line(disp_script.to_s)
      end

      def remove_from_script(script, assistant, id)
        return false unless rm_script = get_script(script)
        cmd = find_by_id(assistant, id)
        vc = VoiceCmd.new(assistant, cmd)
        rm_script.rm(vc)
      end

      def add_to_script(script, assistant, id, fill)
        # Add script to scripts list
        add_script = get_script(script) || VCScript.new(script)
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
          print_error("Could not find voice command id #{id} in #{script}. Script not modified.")
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
          print_error("Could not find script #{script}. Script not written to file.")
        else
          begin
            script_path = write.save(filename)
            print_status("Script #{script} written to '#{script_path}'.")
          rescue IOError => e
            print_error("Script #{script} not written to '#{script_path}'. #{e.message}")
          rescue SystemCallError => e
            print_error("Script #{script} not written to '#{script_path}'. #{e.message}")
          end
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
        return find if find.hash = hash
      end
      nil
    end
  
    def save(filename)
      return unless @vc_list.length > 0

      script_hash = { "Script" => @script, "Assistant" => @assistant}
      cmds = Hash.new
      @vc_list.each do |vc|
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

    def to_s()
      all_cmds = "\nScript '#{@script}':\n"
      @vc_list.each do |vc|
        all_cmds << "#{@vc_list.index(vc) + 1}: #{vc.cmd}\n"
      end
      all_cmds
    end
  end
end

