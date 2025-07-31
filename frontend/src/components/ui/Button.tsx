import React from 'react';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'success' | 'info';
  size?: 'sm' | 'md' | 'lg';
  children: React.ReactNode;
}

const Button: React.FC<ButtonProps> = ({
  variant = 'primary',
  size = 'md',
  className = '',
  disabled = false,
  children,
  ...props
}) => {
  const baseClasses = 'inline-flex items-center justify-center font-medium rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-800 text-center';
  
  const variantClasses = {
    primary: 'bg-blue-100 hover:bg-blue-200 text-blue-900 focus:ring-blue-500 disabled:bg-gray-200 disabled:text-gray-500 disabled:cursor-not-allowed',
    secondary: 'bg-gray-100 hover:bg-gray-200 text-gray-900 focus:ring-gray-500 disabled:bg-gray-200 disabled:text-gray-500 disabled:cursor-not-allowed',
    danger: 'bg-red-100 hover:bg-red-200 text-red-900 focus:ring-red-500 disabled:bg-gray-200 disabled:text-gray-500 disabled:cursor-not-allowed',
    success: 'bg-green-100 hover:bg-green-200 text-green-900 focus:ring-green-500 disabled:bg-gray-200 disabled:text-gray-500 disabled:cursor-not-allowed',
    info: 'bg-blue-50 hover:bg-blue-100 text-blue-800 focus:ring-blue-400 disabled:bg-gray-200 disabled:text-gray-500 disabled:cursor-not-allowed',
  };
  
  const sizeClasses = {
    sm: 'px-3 py-1.5 text-sm min-h-[32px]',
    md: 'px-4 py-2 text-sm min-h-[40px]',
    lg: 'px-6 py-3 text-base min-h-[48px]',
  };

  const classes = `${baseClasses} ${variantClasses[variant]} ${sizeClasses[size]} ${className}`;

  return (
    <button
      className={classes}
      disabled={disabled}
      {...props}
    >
      <span className="flex items-center justify-center w-full">
        {children}
      </span>
    </button>
  );
};

export default Button; 