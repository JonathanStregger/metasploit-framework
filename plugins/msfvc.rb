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
          'vc_list' => 'List available voice commands',
          'vc_help'   => 'Display msfvc help'
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
            ['--category', '-c', GetoptLong::REQUIRED_ARGUMENT]
          )
          
          categories = []
          assistant = ''
          begin
            opts.each do |opt, arg|
              case opt
              when '--help'
                usage_vc_list()
                return
              when '--category'
                if categories.length == 0
                  categories = [arg]  
                else
                  categories << arg
                end
              when '--assistant'
                arg = arg.downcase
                if arg == 'google' || arg == 'hey google' || arg == "google voice assistant"
                  assistant = 'Google voice assistant'
                elsif arg == 'siri' || arg == 'hey siri' || arg == 'apple'
                  assistant = 'Apple Siri'
                elsif arg == 'alexa' || arg == 'amazon'
                  assistant = 'Amazon Alexa'
                elsif arg == '?'
                  print_line("\nSupported voice assistants")
                  print_line("==========================\n")
                  vas = @vc_data.keys
                  vas.each do |va|
                    print_line("    #{va}")
                  end
                  print_line('')
                  return
                else
                  print_error("#{arg} is not a supported voice assistant.")
                  return
                end
              end
            end
          rescue GetoptLong::Error => e
            print_status("#{e}")
          end
          if assistant == ''
            print_error('A voice assistant must be specified with the -a or --assistant option or ? to list available voice assistants')
          else
            display_vc(assistant, categories)
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
        tbl << ['-h, --help', 'Show this help message', 'vc_list --help']
        print("\n#{tbl.to_s}\n")
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

      def display_vc(provider, category = [])
        tbl = Rex::Text::Table.new(
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
        print("\n#{tbl.to_s}\n")
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
