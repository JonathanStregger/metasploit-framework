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
      end

      def commands
        {
          'vc_list'     => 'List available voice commands',
          'vc_details'  => 'Display details for a voice command by id or command text',
          'vc_help'     => 'Display msfvc help'
        }
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

      def display(provider, category = [], cmds = [[]])
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
        if cmds != [[]]
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
        if cmds != [[]]
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
        if (obj == nil)
          return false
        end
        obj.include?(search)
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
end
