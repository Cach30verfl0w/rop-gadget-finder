use std::fs::File;
use std::io::Read;
use capstone::arch::{BuildsCapstone, BuildsCapstoneSyntax};
use capstone::arch::*;
use capstone::{Capstone, Insn, Instructions};
use clap::Parser;
use colored::Colorize;
use goblin::elf::Elf;
use regex::Regex;
use simple_logger::SimpleLogger;
use thiserror::Error;

pub struct GadgetBuilder<'a> {
    capstone: Capstone,
    bytes: &'a [u8],
    address: u64
}

impl<'a> GadgetBuilder<'a> {

    pub fn new(address: u64, bytes: &'a [u8], architecture: Architecture) -> Result<Self, capstone::Error> {
        let capstone = match architecture {
            Architecture::x86 => Capstone::new().x86().mode(x86::ArchMode::Mode64).syntax(x86::ArchSyntax::Intel).build(),
            Architecture::x86_64 => Capstone::new().x86().mode(x86::ArchMode::Mode64).syntax(x86::ArchSyntax::Intel).build(),
            Architecture::ARM => Capstone::new().arm().mode(arm::ArchMode::Arm).build(),
            Architecture::ARM64 => Capstone::new().arm64().mode(arm64::ArchMode::Arm).build()
        }?;

        Ok(Self {
            bytes,
            address,
            capstone
        })
    }

    pub fn find_gadgets(&self, max_instructions: usize) -> Vec<Gadget> {
        let instructions = self.capstone.disasm_all(self.bytes, self.address).unwrap();
        let mut last_jump_instruction = 0usize;

        let mut gadgets = Vec::new();
        for (index, instruction) in instructions.iter().clone().enumerate() {
            match instruction.mnemonic().unwrap() {
                "call" | "je" | "jne" | "jnz" | "jz" => {
                    last_jump_instruction = index
                },
                "jmp" => {
                    if (index as i32 - max_instructions as i32) < 0 {
                        continue;
                    }

                    let first_gadget_instruction = if index - last_jump_instruction > max_instructions {
                        index - max_instructions
                    } else {
                        last_jump_instruction
                    };

                    let mut string_instructions = Vec::new();
                    for i in first_gadget_instruction + 1..index + 1 {
                        let display = format!("{}", instructions.get(i).unwrap());
                        let mut split = display.split(": ");
                        split.next().unwrap();

                        string_instructions.push(split.next().unwrap().to_string());
                    }

                    if string_instructions.len() <= 1 {
                        continue;
                    }

                    gadgets.push(Gadget {
                        address: instructions.get(first_gadget_instruction + 1).unwrap().address(),
                        instructions: string_instructions
                    });

                    last_jump_instruction = index;
                },
                _ => {}
            }
        }
        gadgets
    }

}

#[derive(Debug)]
pub struct Gadget {
    pub address: u64,
    pub instructions: Vec<String>
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub enum Architecture {
    x86,
    x86_64,
    ARM,
    ARM64
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The maximum of instructions in a Gadget
    #[arg(short, long, default_value_t = 32)]
    max_instructions: u16,

    /// The executable or library in that the gadgets should be searched
    target_file: String,

    /// A RegEx which filters all gadgets and only return the matching gadgets
    #[arg(short, long)]
    filter: Option<String>
}

fn main() {
    SimpleLogger::new().env().init().unwrap();
    let arguments = Args::parse();
    let mut file = File::open(arguments.target_file).unwrap();

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    log::info!("Read {} bytes into the program memory", bytes.len());

    let elf = Elf::parse(&bytes).unwrap();
    for section_header in elf.section_headers {
        if !section_header.is_executable() {
            continue;
        }

        let bytes = &bytes.as_slice()[section_header.file_range().unwrap()];
        let gadget_builder = GadgetBuilder::new(section_header.sh_addr, bytes, Architecture::x86_64).unwrap();
        let gadgets = gadget_builder.find_gadgets(8);
        let regex = match &arguments.filter {
            Some(filter) => Some(Regex::new(filter).unwrap()),
            None => None
        };

        for gadget in gadgets {
            if let Some(regex) = &regex {
                let mut single_instruction = String::new();
                for instruction in &gadget.instructions {
                    single_instruction.push_str(instruction.as_str());
                    single_instruction.push_str(" ; ");
                }

                if !regex.is_match(single_instruction.as_str()) {
                    continue;
                }
            }

            print!("{}{}", format!("0x{:X}", gadget.address).red(), ": ".bright_white());
            for i in 0..gadget.instructions.len() {
                print!("{}", gadget.instructions[i].yellow());
                if i != gadget.instructions.len() - 1 {
                    print!(" {} ", ";".bright_white());
                }
            }
            println!();
        }
    }
}
