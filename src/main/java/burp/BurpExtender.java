package burp;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import java.awt.Container;
import java.util.HashSet;
import java.util.Set;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Properties;
import java.util.Collections;
import java.util.Comparator;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IHttpListener, IScannerCheck, IMessageEditorController, IContextMenuFactory {
   
   // 核心成员变量
   private IBurpExtenderCallbacks callbacks;
   private IExtensionHelpers helpers;
   private JSplitPane splitPane;
   
   // 消息查看器
   private IMessageEditor requestViewer;
   private IMessageEditor responseViewer;
   private IMessageEditor requestViewer_1;
   private IMessageEditor responseViewer_1;
   private IMessageEditor requestViewer_2;
   private IMessageEditor responseViewer_2;
   
   
   // 数据存储
   private final List<LogEntry> log = new ArrayList<>();
   private final List<Request_md5> log4_md5 = new ArrayList<>();
   
   // 当前显示项
   private IHttpRequestResponse currentlyDisplayedItem;
   private IHttpRequestResponse currentlyDisplayedItem_1;
   private IHttpRequestResponse currentlyDisplayedItem_2;
   
   // 输出流
   public PrintWriter stdout;
   
   // UI组件
   JTabbedPane tabs;
   JTable logTable;
   
   // 认证配置文本区域引用
   private JTextArea lowPrivilegeTextArea;
   private JTextArea unauthorizedTextArea;
   
   // 控制开关
   int switchs = 0;
   int white_switchs = 0;
   int autoSave_switchs = 0;  // 自动保存开关
   int methodFilter_switchs = 0;  // HTTP方法过滤器开关
   int pathFilter_switchs = 0;  // 接口路径过滤器开关
   
   // 计数器
   int conut = 0;
   int select_row = 0;
   
   // 数据存储
   int original_data_len;
   String temp_data;
   String white_URL = "";
   String data_1 = "";
   String data_2 = "";
   String parameterReplace = "";  // 新增：参数替换配置
   String universal_cookie = "";
   String filteredMethods = "";  // 过滤的HTTP方法列表
   String filteredPaths = "";  // 过滤的接口路径列表
   
   // 性能优化：缓存预分割的过滤数组
   private String[] filteredMethodsArray = null;
   private String[] filteredPathsArray = null;
   
   // 配置选项
   private int maxLogEntries = 1000;  // 最大日志条目数
   private boolean enableDetailedLogging = true;  // 启用详细日志
   private String outputFormat = "TEXT";  // 输出格式：TEXT, JSON, CSV
   
   // 配置文件名
   private static final String CONFIG_FILE = "XiaYue_Pro_config.properties";
   
   // 版本信息
   String xy_version = "2.3";
   
   // 常量
   private static final String[] STATIC_FILE_EXTENSIONS = {
       "jpg", "png", "gif", "css", "js", "pdf", "mp3", 
       "mp4", "avi", "map", "svg", "ico", "woff", "woff2", "ttf"
   };
   
   // UI组件引用，用于配置加载后更新
   private JCheckBox chkbox1_ui;  // 启动插件
   private JCheckBox chkbox2_ui;  // 启动万能cookie
   private JCheckBox chkbox3_ui;  // 自动保存结果
   private JCheckBox chkbox4_ui;  // 启用HTTP方法过滤
   private JCheckBox chkbox5_ui;  // 启用接口路径过滤
   private JTextField textField_ui;  // 白名单域名
   private JTextField methodFilterField_ui;  // HTTP方法过滤
   private JTextField pathFilterField_ui;  // 接口路径过滤
   private JTextField parameterReplaceField_ui;  // 参数替换配置
   private JButton btn1_ui;  // 清空列表按钮
   private JButton btn3_ui;  // 启动白名单按钮
   
   // 数据存储
   // 构造函数
   public BurpExtender() {
       // 初始化代码
   }
   
   // IBurpExtender接口实现
   public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
      this.stdout = new PrintWriter(callbacks.getStdout(), true);
      this.stdout.println("hello xiaYue_Pro!");
      this.stdout.println("你好 欢迎使用 瞎越!");
      this.stdout.println("version:" + this.xy_version);
      this.callbacks = callbacks;
      this.helpers = callbacks.getHelpers();
      callbacks.setExtensionName("xiaYue_Pro V" + this.xy_version);
      
      // 注册右键菜单工厂
      callbacks.registerContextMenuFactory(this);
      
      SwingUtilities.invokeLater(new Runnable() {
         public void run() {
            initializeUI();
         }
      });
   }
   
   // 初始化UI界面
   private void initializeUI() {
      // 创建主分割面板
      this.splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
      JSplitPane splitPanes = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
      JSplitPane splitPanes_2 = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
      
      // 创建表格
      this.logTable = new JTable(this);
      this.logTable.getColumnModel().getColumn(0).setPreferredWidth(10);
      this.logTable.getColumnModel().getColumn(1).setPreferredWidth(50);
      this.logTable.getColumnModel().getColumn(2).setPreferredWidth(300);
      
      // 添加表头点击监听器，支持排序
      this.logTable.getTableHeader().addMouseListener(new java.awt.event.MouseAdapter() {
         @Override
         public void mouseClicked(java.awt.event.MouseEvent e) {
            int column = logTable.columnAtPoint(e.getPoint());
            if (column >= 0) {
               // 使用改进的排序逻辑，支持升序/降序切换
               sortByColumn(column, true);
            }
         }
      });
      
      // 设置表头可点击的视觉提示
      this.logTable.getTableHeader().setReorderingAllowed(false); // 禁止列重排
      this.logTable.getTableHeader().setDefaultRenderer(new javax.swing.table.DefaultTableCellRenderer() {
         @Override
         public java.awt.Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            
            // 显示排序状态
            if (column == lastSortedColumn) {
               String arrow = lastSortAscending ? " ▲" : " ▼";
               setText(value + arrow);
               setForeground(java.awt.Color.BLUE); // 当前排序列显示为蓝色
            } else {
               setText(value + " ▼"); // 未排序列显示默认提示
               setForeground(java.awt.Color.BLACK);
            }
            
            return this;
         }
      });
      
      // 创建滚动面板
      JScrollPane scrollPane = new JScrollPane(this.logTable);
      JPanel jp = new JPanel();
      jp.setLayout(new GridLayout(1, 1));
      jp.add(scrollPane);
      
      // 创建控制面板
      JPanel jps = createControlPanel();
      JPanel jps_2 = createAuthPanel();
      
      // 创建标签页
      this.tabs = createTabbedPane();
      
      // 组装界面
      splitPanes_2.setLeftComponent(jps);
      splitPanes_2.setRightComponent(jps_2);
      splitPanes.setLeftComponent(jp);
      splitPanes.setRightComponent(this.tabs);
      this.splitPane.setLeftComponent(splitPanes);
      this.splitPane.setRightComponent(splitPanes_2);
      this.splitPane.setResizeWeight(0.8);
      this.splitPane.setDividerLocation(0.8);
      
      // 自定义UI组件
      callbacks.customizeUiComponent(this.splitPane);
      callbacks.customizeUiComponent(this.logTable);
      callbacks.customizeUiComponent(scrollPane);
      callbacks.customizeUiComponent(jps);
      callbacks.customizeUiComponent(jp);
      callbacks.customizeUiComponent(this.tabs);
      
      // 添加标签页和注册监听器
      callbacks.addSuiteTab(this);
      callbacks.registerHttpListener(this);
      callbacks.registerScannerCheck(this);
      
      // 表格选择监听：点击行时展示三个数据包
      this.logTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
         @Override
         public void valueChanged(ListSelectionEvent e) {
            if (e.getValueIsAdjusting()) return;
            int selectedRow = logTable.getSelectedRow();
            if (selectedRow < 0 || selectedRow >= log.size()) return;
            LogEntry logEntry = log.get(selectedRow);
            try {
               requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
               responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
               requestViewer_1.setMessage(logEntry.requestResponse_1.getRequest(), true);
               responseViewer_1.setMessage(logEntry.requestResponse_1.getResponse(), false);
               requestViewer_2.setMessage(logEntry.requestResponse_2.getRequest(), true);
               responseViewer_2.setMessage(logEntry.requestResponse_2.getResponse(), false);
               currentlyDisplayedItem = logEntry.requestResponse;
               currentlyDisplayedItem_1 = logEntry.requestResponse_1;
               currentlyDisplayedItem_2 = logEntry.requestResponse_2;
            } catch (Exception ex) {
               stdout.println("展示选中行数据时发生错误: " + ex.getMessage());
            }
         }
      });
      
      // UI初始化完成后加载配置
      loadConfigAfterUI();
   }
   
   // 创建控制面板
   private JPanel createControlPanel() {
      JPanel jps = new JPanel();
      jps.setLayout(new GridLayout(17, 1));  // 从18行减少到17行
      
      JLabel jls = new JLabel("插件名：xiaYue_Pro");
      JLabel jls_2 = new JLabel("版本：xiaYue_Pro V" + this.xy_version);
      this.chkbox1_ui = new JCheckBox("启动插件");
      this.chkbox2_ui = new JCheckBox("启动万能cookie");
      JLabel jls_5 = new JLabel("如果需要多个域名加白请用,隔开");
      this.textField_ui = new JTextField("填写白名单域名");
      this.btn1_ui = new JButton("清空列表");
      this.btn1_ui.addActionListener(new ActionListener() {
         public void actionPerformed(ActionEvent e) {
            SwingUtilities.invokeLater(new Runnable() {
               public void run() {
                  clearAllData();
               }
            });
         }
      });
      this.btn3_ui = new JButton("启动白名单");
      
      // 新增配置选项
      this.chkbox3_ui = new JCheckBox("自动保存结果");
      this.chkbox4_ui = new JCheckBox("启用HTTP方法过滤");
      JButton btn4 = new JButton("高级设置");
      
      // HTTP方法过滤器配置
      JLabel jls_6 = new JLabel("过滤的HTTP方法（用逗号分隔，如：OPTIONS,HEAD）");
      this.methodFilterField_ui = new JTextField(filteredMethods);
      JButton btn5 = new JButton("应用方法过滤");
      
      // 接口路径过滤器配置
      this.chkbox5_ui = new JCheckBox("启用接口路径过滤");
      JLabel jls_7 = new JLabel("过滤的接口路径（用逗号分隔，如：/api/asd/,/admin/）");
      this.pathFilterField_ui = new JTextField(filteredPaths);
      JButton btn6 = new JButton("应用路径过滤");
      
      // 添加事件监听器
      this.chkbox1_ui.addItemListener(new ItemListener() {
         public void itemStateChanged(ItemEvent e) {
            if (chkbox1_ui.isSelected()) {
               BurpExtender.this.switchs = 1;
               BurpExtender.this.data_1 = getAuthTextAreaText(0);
               BurpExtender.this.data_2 = getAuthTextAreaText(1);
               BurpExtender.this.parameterReplace = getAuthTextAreaText(2);
               setAuthTextAreaEditable(0, false);
               setAuthTextAreaEditable(1, false);
               setAuthTextAreaEditable(2, false);
            } else {
               BurpExtender.this.switchs = 0;
               setAuthTextAreaEditable(0, true);
               setAuthTextAreaEditable(1, true);
               setAuthTextAreaEditable(2, true);
            }
            saveConfig();  // 保存配置
         }
      });
      
      this.chkbox2_ui.addItemListener(new ItemListener() {
         public void itemStateChanged(ItemEvent e) {
            if (chkbox2_ui.isSelected()) {
               BurpExtender.this.universal_cookie = "";
            } else {
               BurpExtender.this.universal_cookie = "";
            }
            saveConfig();  // 保存配置
         }
      });
      
      this.btn3_ui.addActionListener(new ActionListener() {
         public void actionPerformed(ActionEvent e) {
            if (btn3_ui.getText().equals("启动白名单")) {
               btn3_ui.setText("关闭白名单");
               BurpExtender.this.white_URL = textField_ui.getText();
               BurpExtender.this.white_switchs = 1;
               textField_ui.setEditable(false);
               textField_ui.setForeground(Color.GRAY);
            } else {
               btn3_ui.setText("启动白名单");
               BurpExtender.this.white_switchs = 0;
               textField_ui.setEditable(true);
               textField_ui.setForeground(Color.BLACK);
            }
            saveConfig();  // 保存配置
         }
      });
      
      // 新增控件的事件监听器
      this.chkbox3_ui.addItemListener(new ItemListener() {
         public void itemStateChanged(ItemEvent e) {
            BurpExtender.this.autoSave_switchs = chkbox3_ui.isSelected() ? 1 : 0;
            saveConfig();  // 保存配置
         }
      });
      
      this.chkbox4_ui.addItemListener(new ItemListener() {
         public void itemStateChanged(ItemEvent e) {
            BurpExtender.this.methodFilter_switchs = chkbox4_ui.isSelected() ? 1 : 0;
            if (chkbox4_ui.isSelected()) {
               methodFilterField_ui.setEditable(false);
               methodFilterField_ui.setForeground(Color.GRAY);
            } else {
               methodFilterField_ui.setEditable(true);
               methodFilterField_ui.setForeground(Color.BLACK);
            }
            saveConfig();  // 保存配置
         }
      });
      
      btn5.addActionListener(new ActionListener() {
         public void actionPerformed(ActionEvent e) {
            if (methodFilter_switchs == 1) {
               filteredMethods = methodFilterField_ui.getText().trim();
               // 允许为空，不强制要求输入
               JOptionPane.showMessageDialog(
                   null,
                   "HTTP方法过滤器已启用，将过滤以下方法：\n" + (filteredMethods.isEmpty() ? "（无，将不过滤任何方法）" : filteredMethods),
                   "瞎越提示",
                   JOptionPane.INFORMATION_MESSAGE
               );
               // 清除缓存数组，确保新配置生效
               filteredMethodsArray = null;
               saveConfig();  // 保存配置
            } else {
               JOptionPane.showMessageDialog(
                   null,
                   "请先启用HTTP方法过滤",
                   "瞎越提示",
                   JOptionPane.WARNING_MESSAGE
               );
            }
         }
      });
      
      // 接口路径过滤器的事件监听器
      this.chkbox5_ui.addItemListener(new ItemListener() {
         public void itemStateChanged(ItemEvent e) {
            BurpExtender.this.pathFilter_switchs = chkbox5_ui.isSelected() ? 1 : 0;
            if (chkbox5_ui.isSelected()) {
               pathFilterField_ui.setEditable(false);
               pathFilterField_ui.setForeground(Color.GRAY);
            } else {
               pathFilterField_ui.setEditable(true);
               pathFilterField_ui.setForeground(Color.BLACK);
            }
            // 清除缓存数组，确保新配置生效
            filteredPathsArray = null;
            saveConfig();  // 保存配置
         }
      });
      
      btn6.addActionListener(new ActionListener() {
         public void actionPerformed(ActionEvent e) {
            if (pathFilter_switchs == 1) {
               filteredPaths = pathFilterField_ui.getText().trim();
               // 允许为空，不强制要求输入
               JOptionPane.showMessageDialog(
                   null,
                   "接口路径过滤器已启用，将过滤以下路径：\n" + (filteredPaths.isEmpty() ? "（无，将不过滤任何路径）" : filteredPaths),
                   "瞎越提示",
                   JOptionPane.INFORMATION_MESSAGE
               );
               // 清除缓存数组，确保新配置生效
               filteredPathsArray = null;
               saveConfig();  // 保存配置
            } else {
               JOptionPane.showMessageDialog(
                   null,
                   "请先启用接口路径过滤",
                   "瞎越提示",
                   JOptionPane.WARNING_MESSAGE
               );
            }
         }
      });
      
      btn4.addActionListener(new ActionListener() {
         public void actionPerformed(ActionEvent e) {
            showAdvancedSettingsDialog();
         }
      });
      
      // 组装控制面板
      jps.add(jls);
      jps.add(jls_2);
      jps.add(chkbox1_ui);
      jps.add(btn1_ui);
      jps.add(jls_5);
      jps.add(textField_ui);
      jps.add(btn3_ui);
      jps.add(chkbox3_ui);
      jps.add(chkbox4_ui);  // 启用HTTP方法过滤
      jps.add(jls_6);
      jps.add(methodFilterField_ui);
      jps.add(btn5);
      jps.add(chkbox5_ui);  // 启用接口路径过滤
      jps.add(jls_7);
      jps.add(pathFilterField_ui);
      jps.add(btn6);
      jps.add(btn4);  // 高级设置
      
      return jps;
   }
   
   // 显示高级设置对话框
   private void showAdvancedSettingsDialog() {
      JPanel settingsPanel = new JPanel();
      settingsPanel.setLayout(new GridLayout(8, 2, 5, 5));
      
      // 最大日志条目数
      settingsPanel.add(new JLabel("最大日志条目数:"));
      JTextField maxLogField = new JTextField(String.valueOf(maxLogEntries));
      settingsPanel.add(maxLogField);
      
      // 启用详细日志
      settingsPanel.add(new JLabel("启用详细日志:"));
      JCheckBox detailedLogBox = new JCheckBox("", enableDetailedLogging);
      settingsPanel.add(detailedLogBox);
      
      // 输出格式
      settingsPanel.add(new JLabel("输出格式:"));
      String[] formats = {"TEXT", "JSON", "CSV"};
      javax.swing.JComboBox<String> formatCombo = new javax.swing.JComboBox<>(formats);
      formatCombo.setSelectedItem(outputFormat);
      settingsPanel.add(formatCombo);
      
      // 自动清理旧数据
      settingsPanel.add(new JLabel("自动清理旧数据:"));
      JCheckBox autoCleanBox = new JCheckBox("", false);
      settingsPanel.add(autoCleanBox);
      
      // 显示对话框
      int result = JOptionPane.showConfirmDialog(
          null,
          settingsPanel,
          "高级设置",
          JOptionPane.OK_CANCEL_OPTION,
          JOptionPane.PLAIN_MESSAGE
      );
      
      // 如果用户点击了确定
      if (result == JOptionPane.OK_OPTION) {
          try {
              // 更新配置
              maxLogEntries = Integer.parseInt(maxLogField.getText());
              enableDetailedLogging = detailedLogBox.isSelected();
              outputFormat = (String) formatCombo.getSelectedItem();
              
              // 应用配置
              applyAdvancedSettings();
              
              // 显示成功消息
              JOptionPane.showMessageDialog(
                  null,
                  "高级设置已更新",
                  "瞎越提示",
                  JOptionPane.INFORMATION_MESSAGE
              );
          } catch (NumberFormatException e) {
              JOptionPane.showMessageDialog(
                  null,
                  "最大日志条目数必须是有效的数字",
                  "设置错误",
                  JOptionPane.ERROR_MESSAGE
              );
          }
      }
   }
   
   // 应用高级设置
   private void applyAdvancedSettings() {
      // 限制日志条目数量
      if (log.size() > maxLogEntries) {
          int removeCount = log.size() - maxLogEntries;
          for (int i = 0; i < removeCount; i++) {
              log.remove(0);
          }
          fireTableDataChanged();
      }
      
      // 输出配置信息
      if (enableDetailedLogging) {
          stdout.println("高级设置已应用:");
          stdout.println("最大日志条目数: " + maxLogEntries);
          stdout.println("输出格式: " + outputFormat);
          stdout.println("详细日志: 启用");
      }
   }
   
   // 创建认证配置面板
   private JPanel createAuthPanel() {
      JPanel jps_2 = new JPanel();
      jps_2.setLayout(new BorderLayout(5, 5));  // 使用BorderLayout，支持组件拉伸
      
      // 创建主面板，使用垂直分割面板
      JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
      mainSplitPane.setDividerLocation(300);  // 设置分割位置
      mainSplitPane.setResizeWeight(0.5);     // 设置分割权重
      
      // 上半部分：越权认证信息
      JPanel topPanel = new JPanel(new BorderLayout(5, 5));
      JLabel jps_2_jls_1 = new JLabel("越权：填写低权限认证信息,将会替换或新增");
      this.lowPrivilegeTextArea = new JTextArea("Cookie: JSESSIONID=test;UUID=1; userid=admin\nAuthorization: Bearer test", 8, 40);  // 增加行数和列数
      this.lowPrivilegeTextArea.setLineWrap(true);  // 启用自动换行
      this.lowPrivilegeTextArea.setWrapStyleWord(true);  // 按单词换行
      JScrollPane jsp = new JScrollPane(this.lowPrivilegeTextArea);
      jsp.setPreferredSize(new java.awt.Dimension(400, 150));  // 设置首选大小
      topPanel.add(jps_2_jls_1, BorderLayout.NORTH);
      topPanel.add(jsp, BorderLayout.CENTER);
      
      // 中间部分：参数替换
      JPanel middlePanel = new JPanel(new BorderLayout(5, 5));
      JLabel jps_2_jls_param = new JLabel("参数替换：填写参数替换规则,格式如：参数名=新值");
      this.parameterReplaceField_ui = new JTextField("", 40);  // 参数替换输入框
      this.parameterReplaceField_ui.setPreferredSize(new java.awt.Dimension(400, 25));  // 设置首选大小
      middlePanel.add(jps_2_jls_param, BorderLayout.NORTH);
      middlePanel.add(parameterReplaceField_ui, BorderLayout.CENTER);
      
      // 下半部分：未授权认证信息
      JPanel bottomPanel = new JPanel(new BorderLayout(5, 5));
      JLabel jps_2_jls_2 = new JLabel("未授权：将移除下列头认证信息,区分大小写");
      this.unauthorizedTextArea = new JTextArea("Cookie\nAuthorization\nToken", 8, 40);  // 增加行数和列数
      this.unauthorizedTextArea.setLineWrap(true);  // 启用自动换行
      this.unauthorizedTextArea.setWrapStyleWord(true);  // 按单词换行
      JScrollPane jsp_1 = new JScrollPane(this.unauthorizedTextArea);
      jsp_1.setPreferredSize(new java.awt.Dimension(400, 150));  // 设置首选大小
      bottomPanel.add(jps_2_jls_2, BorderLayout.NORTH);
      bottomPanel.add(jsp_1, BorderLayout.CENTER);
      
      // 组装分割面板
      JSplitPane topSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
      topSplitPane.setTopComponent(topPanel);
      topSplitPane.setBottomComponent(middlePanel);
      topSplitPane.setDividerLocation(200);  // 设置分割位置
      topSplitPane.setResizeWeight(0.7);     // 设置分割权重
      
      mainSplitPane.setTopComponent(topSplitPane);
      mainSplitPane.setBottomComponent(bottomPanel);
      
      jps_2.add(mainSplitPane, BorderLayout.CENTER);
      
      return jps_2;
   }
   
   // 获取认证文本区域文本
   private String getAuthTextAreaText(int index) {
      if (index == 0) {
         return lowPrivilegeTextArea.getText();
      } else if (index == 1) {
         return unauthorizedTextArea.getText();
      } else if (index == 2) {
         return parameterReplaceField_ui.getText();
      } else {
         return "";
      }
   }
   
   // 设置认证文本区域可编辑性
   private void setAuthTextAreaEditable(int index, boolean editable) {
      if (index == 0) {
         lowPrivilegeTextArea.setEditable(editable);
         lowPrivilegeTextArea.setBackground(editable ? Color.WHITE : Color.LIGHT_GRAY);
      } else if (index == 1) {
         unauthorizedTextArea.setEditable(editable);
         unauthorizedTextArea.setBackground(editable ? Color.WHITE : Color.LIGHT_GRAY);
      } else if (index == 2) {
         parameterReplaceField_ui.setEditable(editable);
         parameterReplaceField_ui.setBackground(editable ? Color.WHITE : Color.LIGHT_GRAY);
      }
   }
   
   // 清空所有数据
   private void clearAllData() {
      // 清空所有数据
      log.clear();
      log4_md5.clear();
      conut = 0;
      
      // 清空当前显示的内容
      requestViewer.setMessage(new byte[0], true);
      responseViewer.setMessage(new byte[0], false);
      requestViewer_1.setMessage(new byte[0], true);
      responseViewer_1.setMessage(new byte[0], false);
      requestViewer_2.setMessage(new byte[0], true);
      responseViewer_2.setMessage(new byte[0], false);
      
      // 对比视图已移除，无需清空
      
      // 重置当前显示项
      currentlyDisplayedItem = null;
      currentlyDisplayedItem_1 = null;
      currentlyDisplayedItem_2 = null;
      
      // 通知表格模型数据已经改变
      fireTableDataChanged();
   }
   
   // 创建标签页
   private JTabbedPane createTabbedPane() {
      JTabbedPane tabs = new JTabbedPane();
      
      // 创建消息查看器
      this.requestViewer = callbacks.createMessageEditor(this, false);
      this.responseViewer = callbacks.createMessageEditor(this, false);
      this.requestViewer_1 = callbacks.createMessageEditor(this, false);
      this.responseViewer_1 = callbacks.createMessageEditor(this, false);
      this.requestViewer_2 = callbacks.createMessageEditor(this, false);
      this.responseViewer_2 = callbacks.createMessageEditor(this, false);
      
      // 创建原始数据包标签页
      JSplitPane y_jp = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
      y_jp.setDividerLocation(500);
      y_jp.setLeftComponent(this.requestViewer.getComponent());
      y_jp.setRightComponent(this.responseViewer.getComponent());
      
      // 创建低权限数据包标签页
      JSplitPane d_jp = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
      d_jp.setDividerLocation(500);
      d_jp.setLeftComponent(this.requestViewer_1.getComponent());
      d_jp.setRightComponent(this.responseViewer_1.getComponent());
      
      // 创建未授权数据包标签页
      JSplitPane w_jp = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
      w_jp.setDividerLocation(500);
      w_jp.setLeftComponent(this.requestViewer_2.getComponent());
      w_jp.setRightComponent(this.responseViewer_2.getComponent());
      
      // 添加标签页
      tabs.addTab("原始数据包", y_jp);
      tabs.addTab("低权限数据包", d_jp);
      tabs.addTab("未授权数据包", w_jp);
      
      // 对比视图标签页已移除
      
      return tabs;
   }
   
   // createDiffTabbedPane 已移除
   
   // updateDiffView 已移除
   
   // 生成差异报告
   private String generateDiffReport(String original, String modified) {
      StringBuilder report = new StringBuilder();
      report.append("=== 差异报告 ===\n\n");
      
      // 分割响应体
      String[] originalLines = original.split("\n");
      String[] modifiedLines = modified.split("\n");
      
      // 单行对比
      int maxLines = Math.max(originalLines.length, modifiedLines.length);
      for (int i = 0; i < maxLines; i++) {
          String originalLine = i < originalLines.length ? originalLines[i] : "";
          String modifiedLine = i < modifiedLines.length ? modifiedLines[i] : "";
          
          if (!originalLine.equals(modifiedLine)) {
              report.append("行 ").append(i + 1).append(":\n");
              report.append("原始响应: ").append(originalLine).append("\n");
              report.append("低权限响应: ").append(modifiedLine).append("\n\n");
          }
      }
      
      // 添加响应长度比较
      int originalLength = original.length();
      int modifiedLength = modified.length();
      report.append("\n=== 长度比较 ===\n");
      report.append("原始响应长度: ").append(originalLength).append("\n");
      report.append("低权限响应长度: ").append(modifiedLength).append("\n");
      report.append("差异: ").append(modifiedLength - originalLength).append(" 字节\n");
      
      return report.toString();
   }
   
   // 显示差异报告对话框
   private void showDiffReportDialog(LogEntry logEntry) {
      if (logEntry == null) return;
      
      try {
          // 获取原始和低权限响应内容
          String originalResponse = helpers.bytesToString(logEntry.requestResponse.getResponse());
          String modifiedResponse = helpers.bytesToString(logEntry.requestResponse_1.getResponse());
          
          // 生成差异报告
          String diffReport = generateDiffReport(originalResponse, modifiedResponse);
          
          // 创建报告显示面板
          JPanel reportPanel = new JPanel();
          reportPanel.setLayout(new BorderLayout());
          
          JTextArea reportArea = new JTextArea(diffReport);
          reportArea.setEditable(false);
          reportArea.setFont(new java.awt.Font("Monospaced", java.awt.Font.PLAIN, 12));
          
          JScrollPane reportScroll = new JScrollPane(reportArea);
          reportPanel.add(reportScroll, BorderLayout.CENTER);
          
          // 显示对话框
          JOptionPane.showMessageDialog(
              null,
              reportPanel,
              "差异报告 - " + logEntry.url,
              JOptionPane.INFORMATION_MESSAGE
          );
          
      } catch (Exception e) {
          stdout.println("生成差异报告时发生错误: " + e.getMessage());
          e.printStackTrace(stdout);
      }
   }
   
   // ITab接口实现
   public String getTabCaption() {
      return "xiaYue_Pro";
   }

   public Component getUiComponent() {
      return this.splitPane;
   }
   
   // IHttpListener接口实现
   public void processHttpMessage(final int toolFlag, boolean messageIsRequest, final IHttpRequestResponse messageInfo) {
      // 只处理响应消息，不处理请求消息
      if (this.switchs == 1 && toolFlag == 4 && !messageIsRequest) {
         // 在进入越权检测之前，先检查原始请求是否需要过滤
         IHttpRequestResponse originalRequest = messageInfo;
         
         // 移除调试信息，提升性能
         // 检查是否需要过滤HTTP方法
         if (methodFilter_switchs == 1) {
            if (shouldFilterRequest(originalRequest)) {
               return; // 直接返回，不打印日志
            }
         }
         
         // 检查是否需要过滤接口路径
         if (pathFilter_switchs == 1) {
            if (shouldFilterPath(originalRequest)) {
               return; // 直接返回，不打印日志
            }
         }
         
         // 使用线程池而不是每次都创建新线程，提升性能
         synchronized(this.log) {
            // 直接在当前线程处理，避免线程创建开销
            try {
               BurpExtender.this.checkVul(messageInfo, toolFlag);
            } catch (Exception var2) {
               var2.printStackTrace();
               BurpExtender.this.stdout.println(var2);
            }
         }
      }
   }
   
   // 检查是否需要过滤HTTP方法 - 性能优化版本
   private boolean shouldFilterRequest(IHttpRequestResponse messageInfo) {
      if (filteredMethods == null || filteredMethods.trim().isEmpty()) {
         return false;
      }
      
      try {
         IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
         String requestMethod = requestInfo.getMethod();
         
         // 预分割过滤方法列表，避免重复分割
         if (filteredMethodsArray == null) {
            String[] methods = filteredMethods.split(",");
            filteredMethodsArray = new String[methods.length];
            for (int i = 0; i < methods.length; i++) {
               filteredMethodsArray[i] = methods[i].trim();
            }
         }
         
         // 快速匹配
         for (String method : filteredMethodsArray) {
            if (method.equalsIgnoreCase(requestMethod)) {
               return true;  // 需要过滤
            }
         }
         
         return false;  // 不需要过滤
      } catch (Exception e) {
         return false; // 静默处理异常，提升性能
      }
   }
   
   // 检查是否需要过滤接口路径 - 性能优化版本
   private boolean shouldFilterPath(IHttpRequestResponse messageInfo) {
      if (filteredPaths == null || filteredPaths.trim().isEmpty()) {
         return false;
      }
      
      try {
         IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
         String requestPath = requestInfo.getUrl().getPath();
         
         // 预分割过滤路径列表，避免重复分割
         if (filteredPathsArray == null) {
            String[] paths = filteredPaths.split(",");
            filteredPathsArray = new String[paths.length];
            for (int i = 0; i < paths.length; i++) {
               filteredPathsArray[i] = paths[i].trim();
            }
         }
         
         // 快速匹配
         for (String path : filteredPathsArray) {
            if (requestPath.contains(path)) {
               return true;  // 需要过滤
            }
         }
         
         return false;  // 不需要过滤
      } catch (Exception e) {
         return false; // 静默处理异常，提升性能
      }
   }
   
   // 核心越权检测方法
   private void checkVul(IHttpRequestResponse baseRequestResponse, int toolFlag) {
      if(!isValidRequest(baseRequestResponse, toolFlag)) {
         return;
      }
      
      if(!processWhitelist(baseRequestResponse)) {
         return; 
      }
      
      String md5 = generateMD5(baseRequestResponse);
      if(isDuplicateRequest(md5)) {
         return;
      }
      
      processRequestAndResponse(baseRequestResponse);
   }
   
   // 验证请求是否有效
   private boolean isValidRequest(IHttpRequestResponse baseRequestResponse, int toolFlag) {
      if(toolFlag != 4 && toolFlag != 64) {
         return false;
      }
      
      String url = helpers.analyzeRequest(baseRequestResponse).getUrl().toString();
      String extension = getFileExtension(url);
      
      return !Arrays.asList(STATIC_FILE_EXTENSIONS).contains(extension);
   }
   
   // 生成MD5值 - 智能去重，只考虑URL路径和方法，忽略参数值
   private String generateMD5(IHttpRequestResponse baseRequestResponse) {
      IRequestInfo analyzeRequest = helpers.analyzeRequest(baseRequestResponse);
      String url = analyzeRequest.getUrl().toString();
      String method = analyzeRequest.getMethod();
      
      // 提取URL路径，忽略查询参数
      String urlPath = url.split("\\?")[0];
      
      // 只考虑URL路径、HTTP方法和参数名（不包含参数值）
      StringBuilder md5Input = new StringBuilder(urlPath);
      md5Input.append("+").append(method);
      
      // 添加参数名，但不包含参数值，这样可以识别相同接口的不同参数组合
      List<IParameter> parameters = analyzeRequest.getParameters();
      if (!parameters.isEmpty()) {
         // 按参数名排序，确保相同参数组合的MD5一致
         List<String> paramNames = new ArrayList<>();
         for (IParameter param : parameters) {
            paramNames.add(param.getName());
         }
         Collections.sort(paramNames); // 排序确保一致性
         
         for (String paramName : paramNames) {
            md5Input.append("+").append(paramName);
         }
      }
      
      String md5Result = MD5(md5Input.toString());
      // 移除调试输出，提升性能
      return md5Result;
   }
   
   // 检查是否为重复请求
   private boolean isDuplicateRequest(String md5) {
      Iterator var29 = this.log4_md5.iterator();

      while(var29.hasNext()) {
         Request_md5 i = (Request_md5)var29.next();
         if (i.md5_data.equals(md5)) {
            return true;
         }
      }

      return false;
   }
   
   // 处理请求和响应
   private void processRequestAndResponse(IHttpRequestResponse baseRequestResponse) {
      this.temp_data = String.valueOf(this.helpers.analyzeRequest(baseRequestResponse).getUrl());
      // 原始响应判空：无响应或无内容则直接返回，不记录
      if (baseRequestResponse.getResponse() == null || baseRequestResponse.getResponse().length == 0) {
         stdout.println("原始数据包无响应，已跳过记录: " + this.temp_data);
         return;
      }
      this.original_data_len = baseRequestResponse.getResponse().length;
      int original_len = this.original_data_len - this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getBodyOffset();
      if (original_len <= 0) {
         stdout.println("原始数据包无内容，已跳过记录: " + this.temp_data);
         return;
      }
      
      String[] temp_data_strarray = this.temp_data.split("\\?");
      String temp_data = temp_data_strarray[0];
      String[] white_URL_list = this.white_URL.split(",");
      boolean white_swith = false;
      
      if (this.white_switchs == 1) {
         white_swith = false;

         for(int i = 0; i < white_URL_list.length; ++i) {
            if (temp_data.contains(white_URL_list[i])) {
               // 移除白名单URL日志，提升性能
               white_swith = true;
            }
         }

         if (!white_swith) {
            // 移除非白名单URL日志，提升性能
            return;
         }
      }

      List<IParameter> paraLists = this.helpers.analyzeRequest(baseRequestResponse).getParameters();

      Iterator var29;
      IParameter para;
      for(var29 = paraLists.iterator(); var29.hasNext(); temp_data = temp_data + "+" + para.getName()) {
         para = (IParameter)var29.next();
      }

      temp_data = temp_data + "+" + this.helpers.analyzeRequest(baseRequestResponse).getMethod();
      
      // 生成MD5
      String md5 = MD5(temp_data);
      
      // 移除MD5日志输出，提升性能
      
      // 检查是否已存在
      var29 = this.log4_md5.iterator();

      while(var29.hasNext()) {
         Request_md5 i = (Request_md5)var29.next();
         if (i.md5_data.equals(md5)) {
            return;
         }
      }

      this.log4_md5.add(new Request_md5(md5));
      
      // 处理低权限请求
      IRequestInfo analyIRequestInfo = this.helpers.analyzeRequest(baseRequestResponse);
      IHttpService iHttpService = baseRequestResponse.getHttpService();
      String request = this.helpers.bytesToString(baseRequestResponse.getRequest());
      int bodyOffset = analyIRequestInfo.getBodyOffset();
      byte[] body = request.substring(bodyOffset).getBytes();
      List<String> headers_y = analyIRequestInfo.getHeaders();
      String[] data_1_list = this.data_1.split("\n");

      int i;
      int low_len;
      for(i = 0; i < headers_y.size(); ++i) {
         String head_key = ((String)headers_y.get(i)).split(":")[0];

         for(low_len = 0; low_len < data_1_list.length; ++low_len) {
            if (head_key.equals(data_1_list[low_len].split(":")[0])) {
               headers_y.remove(i);
               --i;
            }
         }
      }

      for(i = 0; i < data_1_list.length; ++i) {
         headers_y.add(headers_y.size() / 2, data_1_list[i]);
      }

      // 应用参数替换逻辑
      String modifiedUrl = null;
      byte[] modifiedBody = body;
      if (this.parameterReplace != null && !this.parameterReplace.trim().isEmpty()) {
         String[] paramRules = this.parameterReplace.split("\n");
         for (String rule : paramRules) {
            rule = rule.trim();
            if (!rule.isEmpty()) {
               String[] parts = rule.split("=", 2);
               if (parts.length == 2) {
                  String paramName = parts[0].trim();
                  String paramValue = parts[1].trim();
                  
                  // 替换URL中的参数（GET请求参数）
                  String url = analyIRequestInfo.getUrl().toString();
                  if (url.contains(paramName + "=")) {
                     // 使用正则表达式替换参数值
                     url = url.replaceAll(paramName + "=[^&]*", paramName + "=" + paramValue);
                     modifiedUrl = url;  // 只有在实际替换时才更新URL
                     
                     // 更新请求头中的Host（如果需要）
                     for (int h = 0; h < headers_y.size(); h++) {
                        String header = headers_y.get(h);
                        if (header.startsWith("Host:")) {
                           try {
                              java.net.URL newUrl = new java.net.URL(url);
                              headers_y.set(h, "Host: " + newUrl.getHost() + (newUrl.getPort() != -1 ? ":" + newUrl.getPort() : ""));
                           } catch (Exception e) {
                              // 忽略URL解析错误
                           }
                        }
                     }
                  }
                  
                  // 替换POST请求体中的参数
                  if (body != null && body.length > 0) {
                     String bodyString = new String(body);
                     String contentType = "";
                     
                     // 获取Content-Type
                     for (String header : headers_y) {
                        if (header.toLowerCase().startsWith("content-type:")) {
                           contentType = header.toLowerCase();
                           break;
                        }
                     }
                     
                     // 处理application/x-www-form-urlencoded格式
                     if (contentType.contains("application/x-www-form-urlencoded") || 
                         (contentType.isEmpty() && bodyString.contains("=") && bodyString.contains("&"))) {
                        if (bodyString.contains(paramName + "=")) {
                           // 替换表单参数
                           bodyString = bodyString.replaceAll(paramName + "=[^&]*", paramName + "=" + paramValue);
                           modifiedBody = bodyString.getBytes();
                        }
                     }
                     // 处理JSON格式
                     else if (contentType.contains("application/json")) {
                        if (bodyString.contains("\"" + paramName + "\"")) {
                           // 替换JSON参数（简单的字符串替换，适用于大多数情况）
                           bodyString = bodyString.replaceAll("\"" + paramName + "\"\\s*:\\s*\"[^\"]*\"", 
                                                             "\"" + paramName + "\":\"" + paramValue + "\"");
                           bodyString = bodyString.replaceAll("\"" + paramName + "\"\\s*:\\s*[^,}\\]]*", 
                                                             "\"" + paramName + "\":" + paramValue);
                           modifiedBody = bodyString.getBytes();
                        }
                     }
                     // 处理其他格式，进行简单的字符串替换
                     else {
                        if (bodyString.contains(paramName + "=")) {
                           bodyString = bodyString.replaceAll(paramName + "=[^&\\s]*", paramName + "=" + paramValue);
                           modifiedBody = bodyString.getBytes();
                        }
                     }
                  }
               }
            }
         }
      }

      // 如果有URL修改，需要重新构建请求行
      if (modifiedUrl != null) {
         // 从原始请求中提取HTTP方法和路径
         String firstLine = headers_y.get(0);
         String[] firstLineParts = firstLine.split(" ");
         if (firstLineParts.length >= 3) {
            String method = firstLineParts[0];
            String path = modifiedUrl.substring(modifiedUrl.indexOf("/", 8)); // 从协议后开始
            String version = firstLineParts[2];
            
            // 更新第一行（请求行）
            headers_y.set(0, method + " " + path + " " + version);
         }
      }
      
      byte[] newRequest_y = this.helpers.buildHttpMessage(headers_y, modifiedBody);
      IHttpRequestResponse requestResponse_y = this.callbacks.makeHttpRequest(iHttpService, newRequest_y);
      // 低权限响应判空
      if (requestResponse_y.getResponse() == null || requestResponse_y.getResponse().length == 0) {
         stdout.println("低权限数据包无响应，已跳过记录: " + this.temp_data);
         return;
      }
      low_len = requestResponse_y.getResponse().length - this.helpers.analyzeResponse(requestResponse_y.getResponse()).getBodyOffset();
      if (low_len <= 0) {
         stdout.println("低权限数据包无内容，已跳过记录: " + this.temp_data);
         return;
      }
      
      String low_len_data = "";
      if (original_len == 0) {
         low_len_data = Integer.toString(low_len);
      } else if (original_len == low_len) {
         low_len_data = Integer.toString(low_len) + "  ✔";
      } else {
         low_len_data = Integer.toString(low_len) + "  ==> " + Integer.toString(original_len - low_len);
      }

      // 处理未授权请求
      List<String> headers_w = analyIRequestInfo.getHeaders();
      String[] data_2_list = this.data_2.split("\n");

      for(int headerIndex = 0; headerIndex < headers_w.size(); ++headerIndex) {
         String head_key = headers_w.get(headerIndex).split(":")[0];

         for(int j = 0; j < data_2_list.length; ++j) {
            if (head_key.equals(data_2_list[j])) {
               headers_w.remove(headerIndex);
               --headerIndex;
            }
         }
      }

      if (this.universal_cookie.length() != 0) {
         String[] universal_cookies = this.universal_cookie.split("\n");
         headers_w.add(headers_w.size() / 2, universal_cookies[0]);
         headers_w.add(headers_w.size() / 2, universal_cookies[1]);
      }

      byte[] newRequest_w = this.helpers.buildHttpMessage(headers_w, body);
      IHttpRequestResponse requestResponse_w = this.callbacks.makeHttpRequest(iHttpService, newRequest_w);
      // 未授权响应判空
      if (requestResponse_w.getResponse() == null || requestResponse_w.getResponse().length == 0) {
         stdout.println("未授权数据包无响应，已跳过记录: " + this.temp_data);
         return;
      }
      int Unauthorized_len = requestResponse_w.getResponse().length - this.helpers.analyzeResponse(requestResponse_w.getResponse()).getBodyOffset();
      if (Unauthorized_len <= 0) {
         stdout.println("未授权数据包无内容，已跳过记录: " + this.temp_data);
         return;
      }
      
      String original_len_data = "";
      if (original_len == 0) {
         original_len_data = Integer.toString(Unauthorized_len);
      } else if (original_len == Unauthorized_len) {
         original_len_data = Integer.toString(Unauthorized_len) + "  ✔";
      } else {
         original_len_data = Integer.toString(Unauthorized_len) + "  ==> " + Integer.toString(original_len - Unauthorized_len);
      }

      ++this.conut;
      int id = this.conut;
      this.log.add(new LogEntry(id, this.helpers.analyzeRequest(baseRequestResponse).getMethod(), 
         this.callbacks.saveBuffersToTempFiles(baseRequestResponse), 
         this.callbacks.saveBuffersToTempFiles(requestResponse_y), 
         this.callbacks.saveBuffersToTempFiles(requestResponse_w), 
         String.valueOf(this.helpers.analyzeRequest(baseRequestResponse).getUrl()), 
         original_len, low_len_data, original_len_data));
      
      this.fireTableDataChanged();
      try {
         int last = Math.max(0, log.size() - 1);
         this.logTable.setRowSelectionInterval(last, last);
      } catch (Exception ignore) {}
   }
   
   // 处理白名单
   private boolean processWhitelist(IHttpRequestResponse baseRequestResponse) {
      if (white_switchs != 1) {
         return true;
      }
      
      String url = helpers.analyzeRequest(baseRequestResponse).getUrl().toString();
      String[] whiteURLs = white_URL.split(",");
      
      for (String whiteURL : whiteURLs) {
         if (url.contains(whiteURL.trim())) {
            // 移除白名单URL日志，提升性能
            return true;
         }
      }
      
      // 移除非白名单URL日志，提升性能
      return false;
   }
   
   // 获取文件扩展名
   private String getFileExtension(String url) {
      if (url == null) return "";
      int lastDotPos = url.lastIndexOf('.');
      int lastSlashPos = url.lastIndexOf('/');
      if (lastDotPos > lastSlashPos && lastDotPos < url.length() - 1) {
         String ext = url.substring(lastDotPos + 1);
         int paramIndex = ext.indexOf('?');
         if (paramIndex > 0) {
            ext = ext.substring(0, paramIndex);
         }
         return ext.toLowerCase();
      }
      return "";
   }
   
   // IScannerCheck接口实现
   public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
      return null;
   }

   public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
      return null;
   }

   public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
      return existingIssue.getIssueName().equals(newIssue.getIssueName()) ? -1 : 0;
   }
   
   // IMessageEditorController接口实现
   public byte[] getRequest() {
      return this.currentlyDisplayedItem.getRequest();
   }

   public byte[] getResponse() {
      return this.currentlyDisplayedItem.getResponse();
   }

   public IHttpService getHttpService() {
      return this.currentlyDisplayedItem.getHttpService();
   }
   
   // AbstractTableModel实现
   public int getRowCount() {
      return this.log.size();
   }

   public int getColumnCount() {
      return 6;
   }

   public String getColumnName(int columnIndex) {
      switch(columnIndex) {
      case 0:
         return "#";
      case 1:
         return "类型";
      case 2:
         return "URL";
      case 3:
         return "原始包长度";
      case 4:
         return "低权限包长度";
      case 5:
         return "未授权包长度";
      default:
         return "";
      }
   }

   public Class<?> getColumnClass(int columnIndex) {
      switch(columnIndex) {
      case 0: return Integer.class;  // ID列
      case 1: return String.class;   // 类型列
      case 2: return String.class;   // URL列
      case 3: return String.class;   // 原始包长度列（以字符串显示，避免渲染异常）
      case 4: return String.class;   // 低权限包长度列
      case 5: return String.class;   // 未授权包长度列
      default: return String.class;
      }
   }

   public Object getValueAt(int rowIndex, int columnIndex) {
      LogEntry logEntry = (LogEntry)this.log.get(rowIndex);
      switch(columnIndex) {
      case 0:
         return Integer.valueOf(logEntry.id);  // 使用原始ID
      case 1:
         return logEntry.Method;
      case 2:
         return logEntry.url;
      case 3:
         return String.valueOf(logEntry.original_len);
      case 4:
         return logEntry.low_len;
      case 5:
         return logEntry.Unauthorized_len;
      default:
         return "";
      }
   }
   
   // 添加排序功能
   public boolean isCellEditable(int rowIndex, int columnIndex) {
      return false; // 表格不可编辑
   }
   
   // 排序状态管理
   private int lastSortedColumn = -1;
   private boolean lastSortAscending = true;
   
   // 排序方法
   public void sortByColumn(int columnIndex, boolean ascending) {
      if (log.isEmpty()) return;
      
      // 如果点击的是同一列，则切换排序方向
      if (lastSortedColumn == columnIndex) {
         ascending = !lastSortAscending;
      }
      
      lastSortedColumn = columnIndex;
      lastSortAscending = ascending;
      
      // 将变量声明为final，以便在内部类中使用
      final int finalColumnIndex = columnIndex;
      final boolean finalAscending = ascending;
      
      Collections.sort(log, new Comparator<LogEntry>() {
         @Override
         public int compare(LogEntry o1, LogEntry o2) {
            int result = 0;
            
            switch (finalColumnIndex) {
               case 0: // ID列
                  result = Integer.compare(o1.id, o2.id);
                  break;
               case 1: // 类型列
                  result = o1.Method.compareTo(o2.Method);
                  break;
               case 2: // URL列
                  result = o1.url.compareTo(o2.url);
                  break;
               case 3: // 原始包长度列
                  result = Integer.compare(o1.original_len, o2.original_len);
                  break;
               case 4: // 低权限包长度列
                  result = o1.low_len.compareTo(o2.low_len);
                  break;
               case 5: // 未授权包长度列
                  result = o1.Unauthorized_len.compareTo(o2.Unauthorized_len);
                  break;
               default:
                  result = 0;
            }
            
            return finalAscending ? result : -result;
         }
      });
      
      fireTableDataChanged();
      // 移除排序调试信息，提升性能
   }
   
   // IContextMenuFactory接口实现
   public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
      List<JMenuItem> menuItems = new ArrayList<>();
      
      // 创建菜单项
      JMenuItem sendToXiaYue = new JMenuItem("发送到瞎越检测");
      sendToXiaYue.addActionListener(new ActionListener() {
          @Override
          public void actionPerformed(ActionEvent e) {
              IHttpRequestResponse[] messages = invocation.getSelectedMessages();
              if (messages != null && messages.length > 0) {
                  // 确保插件已启动
                  if (switchs == 1) {
                      for (IHttpRequestResponse message : messages) {
                          // 在新线程中处理请求，避免阻塞UI
                          new Thread(() -> {
                              try {
                                  checkVul(message, 4); // 使用 TOOL_PROXY(4) 作为工具标识
                              } catch (Exception ex) {
                                  stdout.println("处理请求时发生错误: " + ex.getMessage());
                                  ex.printStackTrace(stdout);
                              }
                          }).start();
                      }
                  } else {
                      // 如果插件未启动，提示信息
                      JOptionPane.showMessageDialog(
                          null,
                          "请先启动插件！",
                          "瞎越提示",
                          JOptionPane.WARNING_MESSAGE
                      );
                  }
              }
          }
      });
      
      // 新增提取认证信息的菜单项
      JMenuItem extractAuth = new JMenuItem("提取认证信息");
      extractAuth.addActionListener(new ActionListener() {
          @Override
          public void actionPerformed(ActionEvent e) {
              IHttpRequestResponse[] messages = invocation.getSelectedMessages();
              if (messages != null && messages.length > 0) {
                  IHttpRequestResponse message = messages[0];
                  
                  // 获取请求信息
                  IRequestInfo requestInfo = helpers.analyzeRequest(message);
                  List<String> headers = requestInfo.getHeaders();
                  
                  // 提取认证信息
                  StringBuilder authInfo = new StringBuilder();    // 完整的认证信息
                  StringBuilder authFields = new StringBuilder();  // 认证字段名
                  
                  // 遍历所有请求头
                  for (String header : headers) {
                      header = header.trim();
                      // 跳过请求行（第一行）
                      if (header.startsWith("POST ") || header.startsWith("GET ") || 
                          header.startsWith("PUT ") || header.startsWith("DELETE ")) {
                          continue;
                      }
                      
                      // 检查是否是认证相关头
                      if (header.toLowerCase().startsWith("cookie:") || 
                          header.toLowerCase().startsWith("authorization:") || 
                          header.toLowerCase().startsWith("token:")) {
                          // 添加完整认证信息
                          authInfo.append(header).append("\n");
                          
                          // 提取字段名
                          String fieldName = header.split(":")[0].trim();
                          if (!authFields.toString().contains(fieldName)) {
                              authFields.append(fieldName).append("\n");
                          }
                      }
                  }
                  
                  // 如果找到认证信息，更新UI
                  if (authInfo.length() > 0) {
                      final String finalAuthInfo = authInfo.toString().trim();
                      final String finalAuthFields = authFields.toString().trim();
                      
                      SwingUtilities.invokeLater(new Runnable() {
                          @Override
                          public void run() {
                              // 更新认证配置区域
                              updateAuthTextAreas(finalAuthInfo, finalAuthFields);
                          }
                      });
                      
                      // 显示成功消息
                      JOptionPane.showMessageDialog(
                          null,
                          "已成功提取认证信息",
                          "瞎越提示",
                          JOptionPane.INFORMATION_MESSAGE
                      );
                  } else {
                      // 创建手动输入对话框
                      JPanel inputPanel = new JPanel();
                      inputPanel.setLayout(new BorderLayout());
                      
                      // 创建文本区域和滚动面板
                      JTextArea inputArea = new JTextArea(5, 30);
                      inputArea.setText("X-Token: your_token_here\nX-User-Id: your_user_id_here");
                      JScrollPane scrollPane = new JScrollPane(inputArea);
                      
                      // 添加说明标签
                      JLabel label = new JLabel("请输入认证信息（每行一个，格式：Header: Value）：");
                      inputPanel.add(label, BorderLayout.NORTH);
                      inputPanel.add(scrollPane, BorderLayout.CENTER);
                      
                      // 显示对话框
                      int result = JOptionPane.showConfirmDialog(
                          null,
                          inputPanel,
                          "无法提取认证信息",
                          JOptionPane.OK_CANCEL_OPTION,
                          JOptionPane.PLAIN_MESSAGE
                      );
                      
                      // 如果用户点击了确定
                      if (result == JOptionPane.OK_OPTION) {
                          String manualInput = inputArea.getText().trim();
                          if (!manualInput.isEmpty()) {
                              // 更新UI
                              SwingUtilities.invokeLater(new Runnable() {
                                  @Override
                                  public void run() {
                                      updateAuthTextAreas(manualInput, null);
                                  }
                              });
                              
                              // 显示成功消息
                              JOptionPane.showMessageDialog(
                                  null,
                                  "已成功添加认证信息",
                                  "瞎越提示",
                                  JOptionPane.INFORMATION_MESSAGE
                              );
                          }
                      }
                  }
              }
          }
      });
      
      // 新增快速配置菜单项
      JMenuItem quickConfig = new JMenuItem("快速配置");
      quickConfig.addActionListener(new ActionListener() {
          @Override
          public void actionPerformed(ActionEvent e) {
              showQuickConfigDialog();
          }
      });
      
      menuItems.add(sendToXiaYue);
      menuItems.add(extractAuth);
      menuItems.add(quickConfig);
      return menuItems;
   }
   
   // 更新认证文本区域
   private void updateAuthTextAreas(String authInfo, String authFields) {
      if (authInfo != null && !authInfo.isEmpty()) {
          // 更新低权限认证信息
          lowPrivilegeTextArea.setText(authInfo);
      }
      
      if (authFields != null && !authFields.isEmpty()) {
          // 更新未授权认证字段
          unauthorizedTextArea.setText(authFields);
      }
   }
   
   // 显示快速配置对话框
   private void showQuickConfigDialog() {
      JPanel configPanel = new JPanel();
      configPanel.setLayout(new GridLayout(12, 2, 5, 5));  // 从10行增加到12行，增加参数替换字段
      
      // 低权限认证配置
      configPanel.add(new JLabel("低权限认证信息:"));
      JTextArea lowAuthArea = new JTextArea(3, 25);
      lowAuthArea.setText(lowPrivilegeTextArea.getText());
      JScrollPane lowAuthScroll = new JScrollPane(lowAuthArea);
      configPanel.add(lowAuthScroll);
      
      // 参数替换配置
      configPanel.add(new JLabel("参数替换规则:"));
      JTextField parameterReplaceField = new JTextField(parameterReplace);
      configPanel.add(parameterReplaceField);
      
      // 未授权认证字段
      configPanel.add(new JLabel("未授权认证字段:"));
      JTextArea unauthArea = new JTextArea(3, 25);
      unauthArea.setText(unauthorizedTextArea.getText());
      JScrollPane unauthScroll = new JScrollPane(unauthArea);
      configPanel.add(unauthScroll);
      
      // 白名单配置
      configPanel.add(new JLabel("白名单域名:"));
      JTextField whitelistField = new JTextField(white_URL);
      configPanel.add(whitelistField);
      
      // HTTP方法过滤器配置
      configPanel.add(new JLabel("过滤的HTTP方法:"));
      JTextField methodFilterField = new JTextField(filteredMethods);
      configPanel.add(methodFilterField);
      
      // 接口路径过滤器配置
      configPanel.add(new JLabel("过滤的接口路径:"));
      JTextField pathFilterField = new JTextField(filteredPaths);
      configPanel.add(pathFilterField);
      
      // 显示对话框
      int result = JOptionPane.showConfirmDialog(
          null,
          configPanel,
          "快速配置",
          JOptionPane.OK_CANCEL_OPTION,
          JOptionPane.PLAIN_MESSAGE
      );
      
      // 如果用户点击了确定
      if (result == JOptionPane.OK_OPTION) {
          // 更新配置
          lowPrivilegeTextArea.setText(lowAuthArea.getText());
          parameterReplace = parameterReplaceField.getText();
          unauthorizedTextArea.setText(unauthArea.getText());
          white_URL = whitelistField.getText();
          filteredMethods = methodFilterField.getText();
          filteredPaths = pathFilterField.getText(); // 更新接口路径过滤器
          
          // 清除缓存数组，确保新配置生效
          filteredMethodsArray = null;
          filteredPathsArray = null;
          
          // 保存配置到文件
          saveConfig();
          
          // 显示成功消息
          JOptionPane.showMessageDialog(
              null,
              "配置已更新并保存",
              "瞎越提示",
              JOptionPane.INFORMATION_MESSAGE
          );
      }
   }
   
   // 内部类：LogEntry - 日志条目数据模型
   private static class LogEntry {
      final int id;
      final String Method;
      final IHttpRequestResponsePersisted requestResponse;
      final IHttpRequestResponsePersisted requestResponse_1;
      final IHttpRequestResponsePersisted requestResponse_2;
      final String url;
      final int original_len;
      final String low_len;
      final String Unauthorized_len;

      LogEntry(int id, String Method, IHttpRequestResponsePersisted requestResponse, 
               IHttpRequestResponsePersisted requestResponse_1, 
               IHttpRequestResponsePersisted requestResponse_2, 
               String url, int original_len, String low_len, String Unauthorized_len) {
         this.id = id;
         this.Method = Method;
         this.requestResponse = requestResponse;
         this.requestResponse_1 = requestResponse_1;
         this.requestResponse_2 = requestResponse_2;
         this.url = url;
         this.original_len = original_len;
         this.low_len = low_len;
         this.Unauthorized_len = Unauthorized_len;
      }
   }
   
   // 内部类：Request_md5 - 请求MD5数据模型
   private static class Request_md5 {
      final String md5_data;

      Request_md5(String md5_data) {
         this.md5_data = md5_data;
      }
   }
   
   // 工具方法
   public static String MD5(String key) {
      char[] hexDigits = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

      try {
         byte[] btInput = key.getBytes();
         MessageDigest mdInst = MessageDigest.getInstance("MD5");
         mdInst.update(btInput);
         byte[] md = mdInst.digest();
         int j = md.length;
         char[] str = new char[j * 2];
         int k = 0;

         for(int i = 0; i < j; ++i) {
            byte byte0 = md[i];
            str[k++] = hexDigits[byte0 >>> 4 & 15];
            str[k++] = hexDigits[byte0 & 15];
         }

         return new String(str);
      } catch (Exception var10) {
         return null;
      }
   }
   
   // 保存配置到文件
   private void saveConfig() {
      try {
         Properties props = new Properties();
         
         // 保存开关状态
         props.setProperty("switchs", String.valueOf(switchs));
         props.setProperty("white_switchs", String.valueOf(white_switchs));
         props.setProperty("autoSave_switchs", String.valueOf(autoSave_switchs));
         props.setProperty("methodFilter_switchs", String.valueOf(methodFilter_switchs));
         props.setProperty("pathFilter_switchs", String.valueOf(pathFilter_switchs));
         
         // 保存配置数据
         props.setProperty("white_URL", white_URL);
         props.setProperty("data_1", data_1);
         props.setProperty("data_2", data_2);
         props.setProperty("parameterReplace", parameterReplace);
         props.setProperty("filteredMethods", filteredMethods);
         props.setProperty("filteredPaths", filteredPaths);
         
         // 移除排序状态保存
         
         // 保存到Burp Suite的扩展目录
         String configPath = callbacks.getExtensionFilename();
         if (configPath != null) {
            File configFile = new File(new File(configPath).getParent(), CONFIG_FILE);
            FileOutputStream out = new FileOutputStream(configFile);
            props.store(out, "XiaYue_Pro Configuration");
            out.close();
            // 移除配置保存日志，提升性能
         }
      } catch (Exception e) {
         stdout.println("保存配置时发生错误: " + e.getMessage());
      }
   }
   
   // 从文件恢复配置
   private void loadConfig() {
      try {
         String configPath = callbacks.getExtensionFilename();
         if (configPath != null) {
            File configFile = new File(new File(configPath).getParent(), CONFIG_FILE);
            if (configFile.exists()) {
               Properties props = new Properties();
               FileInputStream in = new FileInputStream(configFile);
               props.load(in);
               in.close();
               
               // 恢复开关状态
               switchs = Integer.parseInt(props.getProperty("switchs", "0"));
               white_switchs = Integer.parseInt(props.getProperty("white_switchs", "0"));
               autoSave_switchs = Integer.parseInt(props.getProperty("autoSave_switchs", "0"));
               methodFilter_switchs = Integer.parseInt(props.getProperty("methodFilter_switchs", "0"));
               pathFilter_switchs = Integer.parseInt(props.getProperty("pathFilter_switchs", "0"));
               
               // 恢复配置数据
               white_URL = props.getProperty("white_URL", "");
               data_1 = props.getProperty("data_1", "");
               data_2 = props.getProperty("data_2", "");
               parameterReplace = props.getProperty("parameterReplace", "");
               filteredMethods = props.getProperty("filteredMethods", "");
               filteredPaths = props.getProperty("filteredPaths", "");
               
               // 移除排序状态恢复
               
               // 移除配置恢复日志，提升性能
            }
         }
      } catch (Exception e) {
         stdout.println("恢复配置时发生错误: " + e.getMessage());
      }
   }
   
   // 在UI初始化完成后加载配置
   private void loadConfigAfterUI() {
      SwingUtilities.invokeLater(new Runnable() {
         public void run() {
            loadConfig();
            // 更新UI状态以反映加载的配置
            updateUIFromConfig();
         }
      });
   }
   
   // 根据配置更新UI状态
   private void updateUIFromConfig() {
      try {
         // 更新复选框状态
         if (chkbox1_ui != null) {
            chkbox1_ui.setSelected(switchs == 1);
         }
         if (chkbox2_ui != null) {
            chkbox2_ui.setSelected(false); // 万能cookie默认不选中
         }
         if (chkbox3_ui != null) {
            chkbox3_ui.setSelected(autoSave_switchs == 1);
         }
         if (chkbox4_ui != null) {
            chkbox4_ui.setSelected(methodFilter_switchs == 1);
         }
         if (chkbox5_ui != null) {
            chkbox5_ui.setSelected(pathFilter_switchs == 1);
         }
         
         // 更新文本字段
         if (textField_ui != null) {
            textField_ui.setText(white_URL);
            // 根据白名单状态设置字段可编辑性
            if (white_switchs == 1) {
               textField_ui.setEditable(false);
               textField_ui.setForeground(Color.GRAY);
            } else {
               textField_ui.setEditable(true);
               textField_ui.setForeground(Color.BLACK);
            }
         }
         
         if (methodFilterField_ui != null) {
            methodFilterField_ui.setText(filteredMethods);
            // 根据过滤器状态设置字段可编辑性
            if (methodFilter_switchs == 1) {
               methodFilterField_ui.setEditable(false);
               methodFilterField_ui.setForeground(Color.GRAY);
            } else {
               methodFilterField_ui.setEditable(true);
               methodFilterField_ui.setForeground(Color.BLACK);
            }
         }
         
         if (pathFilterField_ui != null) {
            pathFilterField_ui.setText(filteredPaths);
            // 根据过滤器状态设置字段可编辑性
            if (pathFilter_switchs == 1) {
               pathFilterField_ui.setEditable(false);
               pathFilterField_ui.setForeground(Color.GRAY);
            } else {
               pathFilterField_ui.setEditable(true);
               pathFilterField_ui.setForeground(Color.BLACK);
            }
         }
         
         // 更新白名单按钮状态
         if (btn3_ui != null) {
            if (white_switchs == 1) {
               btn3_ui.setText("关闭白名单");
            } else {
               btn3_ui.setText("启动白名单");
            }
         }
         
         // 更新认证文本区域
         if (lowPrivilegeTextArea != null) {
            lowPrivilegeTextArea.setText(data_1);
         }
         if (unauthorizedTextArea != null) {
            unauthorizedTextArea.setText(data_2);
         }
         if (parameterReplaceField_ui != null) {
            parameterReplaceField_ui.setText(parameterReplace);
         }
         
         // 根据插件状态设置认证区域可编辑性
         if (switchs == 1) {
            setAuthTextAreaEditable(0, false);
            setAuthTextAreaEditable(1, false);
         } else {
            setAuthTextAreaEditable(0, true);
            setAuthTextAreaEditable(1, true);
         }
         
         // 移除UI状态更新日志，提升性能
      } catch (Exception e) {
         stdout.println("更新UI状态时发生错误: " + e.getMessage());
         e.printStackTrace(stdout);
      }
   }
}
