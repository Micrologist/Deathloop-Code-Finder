﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Windows;

namespace Deathloop_Code_Finder
{
	public partial class MainWindow : Window
	{
		private static readonly DeepPointer codeArray = new DeepPointer(0x03296138, 0x0);
		private static readonly int[] codeIndices = new int[9] { 93, 92, 33, 60, 61, 62, 97, 147, 26 };
		private static readonly string[] pumpStationLookup = new string[9] { "11", "08", "16", "07", "41", "25", "35", "24", "04" };

		private static readonly string[] currentCodes = new string[9];

		public MainWindow()
		{
			InitializeComponent();
		}

		private void Scan()
		{
			codeBlock.Text = "";
			Process proc = Hook();
			if (proc == null)
			{
				return;
			}

			_ = codeArray.DerefOffsets(proc, out IntPtr arrayPtr);

			for (int i = 0; i < codeIndices.Length; i++)
			{
				if (i > 0)
				{
					codeBlock.Text += "\n";
				}

				int index = codeIndices[i];
				_ = proc.ReadValue(arrayPtr + ((index + 1) * 0x10), out IntPtr codePtr);
				if (codePtr == IntPtr.Zero)
				{
					continue;
				}

				_ = proc.ReadBytes(codePtr, 16, out byte[] codeBytes);

				string codeString = "";
				for (int c = 0; c < 4; c++)
				{
					codeString += codeBytes[c * 4].ToString();
				}

				currentCodes[i] = codeString;

				switch (index)
				{
					case 60:
					{
						codeString = codeString.Substring(0, 3);
						break;
					}
					case 62:
					{
						char letter = (char)(codeString[0] + (char)0x11);
						codeString = letter + codeString.Substring(1);
						break;
					}
					case 26:
					{
						string translatedCodeString = "";
						for (int i1 = 0; i1 < codeString.Length; i1++)
						{
							translatedCodeString += pumpStationLookup[int.Parse(codeString.Substring(i1, 1))];
							if (i1 < codeString.Length - 1) translatedCodeString += " ";
						}
						codeString = translatedCodeString;
						break;
					}

					default:
						break;
				}

				codeBlock.Text += codeString;

			}
		}

		private Process Hook()
		{
			List<Process> processList = Process.GetProcesses().ToList().FindAll(x => x.ProcessName == "Deathloop");
			if (processList.Count == 0)
			{
				return null;
			}
			Process proc = processList[0];
			return proc.HasExited ? null : proc;
		}

		private void SaveBtn_Click(object sender, RoutedEventArgs e)
		{
			e.Handled = true;
			Scan();
		}

		private void CopyBtn_Click(object sender, RoutedEventArgs e)
		{
			e.Handled = true;
			Clipboard.SetText(string.Join("\n", currentCodes));
		}
	}
}